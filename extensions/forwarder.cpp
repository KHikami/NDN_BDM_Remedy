/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2016,  Regents of the University of California,
 *                           Arizona Board of Regents,
 *                           Colorado State University,
 *                           University Pierre & Marie Curie, Sorbonne University,
 *                           Washington University in St. Louis,
 *                           Beijing Institute of Technology,
 *                           The University of Memphis.
 *
 * This file is part of NFD (Named Data Networking Forwarding Daemon).
 * See AUTHORS.md for complete list of NFD authors and contributors.
 *
 * NFD is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * NFD is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NFD, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "forwarder.hpp"
#include "algorithm.hpp"
#include "core/logger.hpp"
#include "strategy.hpp"
#include "table/cleanup.hpp"
#include <ndn-cxx/lp/tags.hpp>
#include "face/null-face.hpp"
#include <boost/random/uniform_int_distribution.hpp>
#include <chrono>

using namespace std;

namespace nfd {

NFD_LOG_INIT("Forwarder");

Forwarder::Forwarder()
  : m_unsolicitedDataPolicy(new fw::DefaultUnsolicitedDataPolicy())
  , m_fib(m_nameTree)
  , m_pit(m_nameTree)
  , m_measurements(m_nameTree)
  , m_strategyChoice(m_nameTree, fw::makeDefaultStrategy(*this))
  , m_csFace(face::makeNullFace(FaceUri("contentstore://")))
{
  fw::installStrategies(*this);
  getFaceTable().addReserved(m_csFace, face::FACEID_CONTENT_STORE);

  m_faceTable.afterAdd.connect([this] (Face& face) {
    face.afterReceiveInterest.connect(
      [this, &face] (const Interest& interest) {
        this->startProcessInterest(face, interest);
      });
    face.afterReceiveData.connect(
      [this, &face] (const Data& data) {
        this->startProcessData(face, data);
      });
    face.afterReceiveNack.connect(
      [this, &face] (const lp::Nack& nack) {
        this->startProcessNack(face, nack);
      });
  });

  m_faceTable.beforeRemove.connect([this] (Face& face) {
    cleanupOnFaceRemoval(m_nameTree, m_fib, m_pit, face);
  });
}

Forwarder::~Forwarder() = default;

void
Forwarder::startProcessInterest(Face& face, const Interest& interest)
{
  // check fields used by forwarding are well-formed
  try {
    if (interest.hasLink()) {
      interest.getLink();
    }
  }
  catch (const tlv::Error&) {
    NFD_LOG_DEBUG("startProcessInterest face=" << face.getId() <<
                  " interest=" << interest.getName() << " malformed");
    // It's safe to call interest.getName() because Name has been fully parsed
    return;
  }

  this->onIncomingInterest(face, interest);
}

void
Forwarder::startProcessData(Face& face, const Data& data)
{
  // check fields used by forwarding are well-formed
  // (none needed)

  this->onIncomingData(face, data);
}

void
Forwarder::startProcessNack(Face& face, const lp::Nack& nack)
{
  // check fields used by forwarding are well-formed
  try {
    if (nack.getInterest().hasLink()) {
      nack.getInterest().getLink();
    }
  }
  catch (const tlv::Error&) {
    NFD_LOG_DEBUG("startProcessNack face=" << face.getId() <<
                  " nack=" << nack.getInterest().getName() <<
                  "~" << nack.getReason() << " malformed");
    return;
  }

  this->onIncomingNack(face, nack);
}


void
Forwarder::onIncomingInterest(Face& inFace, const Interest& interest)
{
  // receive Interest
  NFD_LOG_DEBUG("onIncomingInterest face=" << inFace.getId() <<
                " interest=" << interest.getName());
  interest.setTag(make_shared<lp::IncomingFaceIdTag>(inFace.getId()));
  ++m_counters.nInInterests;

  // /localhost scope control
  bool isViolatingLocalhost = inFace.getScope() == ndn::nfd::FACE_SCOPE_NON_LOCAL &&
                              scope_prefix::LOCALHOST.isPrefixOf(interest.getName());
  if (isViolatingLocalhost) {
    NFD_LOG_DEBUG("onIncomingInterest face=" << inFace.getId() <<
                  " interest=" << interest.getName() << " violates /localhost");
    // (drop)
    return;
  }

  // detect duplicate Nonce with Dead Nonce List
  bool hasDuplicateNonceInDnl = m_deadNonceList.has(interest.getName(), interest.getNonce());
  if (hasDuplicateNonceInDnl) {
    // goto Interest loop pipeline
    this->onInterestLoop(inFace, interest);
    return;
  }

  //undoing the const part so we can swap out the interests...
  Interest& goodInterest = const_cast<Interest&>(interest);

  //TO-Do: If exclude interest => create non-exclude version
  bool hasExclude = interest.toUri().find("ndn.Exclude")!= std::string::npos;
  shared_ptr<pit::Entry> pitEntry;

  if(hasExclude)
  {
     Interest excludelessInterest = Interest(interest.getName(), interest.getInterestLifetime());
     excludelessInterest.setNonce(interest.getNonce());
     pitEntry = m_pit.insert(excludelessInterest).first;
     goodInterest = excludelessInterest;
  }
  else
  {
    // PIT insert
    pitEntry = m_pit.insert(interest).first;
  }

  // detect duplicate Nonce in PIT entry. Note: if new interest has exclude => still hits for this :P
  bool hasDuplicateNonceInPit = fw::findDuplicateNonce(*pitEntry, interest.getNonce(), inFace) !=
                                fw::DUPLICATE_NONCE_NONE;

  if (hasDuplicateNonceInPit) {
    //need to check if this is an exclude interest => interest.toUri() contains exclude=...
    //interest is: /prefix/data/%FE%07?ndn.InterestLifetime=2000&ndn.Nonce=3530243069&ndn.Exclude=evil
    cout << "duplicate nonce received for matching pit entry!" << endl;

    if(hasExclude)
    {
      //exclude field exists for this interest
       pit::InRecordCollection::iterator inRecord = pitEntry->getInRecord(inFace);

       //do I need to check if exclude was previously set???
       if(inRecord->getInPreviousRemedy())
       {
         inRecord->setReceivedExclude(true);
         //set received exclude
         cout<<"Interest was in previous remedy and this is an exclude. Checking if Remedy Needed"<<endl;
         NFD_LOG_DEBUG("Checking if " << pitEntry << " needs a remedy");

        double excludeReceivedCount = 0;
        double numOfRecords = 0;
        for (const pit::InRecord& remedyRecord : pitEntry->getInRecords()) {
            if (remedyRecord.getReceivedExclude()) {
               excludeReceivedCount++;
            }
            numOfRecords++;
        }

        double triggerRatio = 0.5;

        if(excludeReceivedCount/numOfRecords > triggerRatio)
        {
           //trigger remedy
           pitEntry->setAwaitingRemedy(true);
           //Send out remedy interest => send the exclude interest.
           cout<< "Remedy Triggered for " << pitEntry->getInRecord(inFace)->getInterest().toUri() << endl;
           NFD_LOG_DEBUG("Remedy for " << pitEntry->getInRecord(inFace)->getInterest().toUri() << " triggered");

           //setting interest into the exclude interest???
           goodInterest = interest;
        } 
        
       }
       else
       {
         //give this one the cached response => have to get the exludeless interest
         cout<<"Attempting to give interest cached info"<<endl;
         const Data& data = pitEntry->getRespondedData();
         beforeSatisfyInterest(*pitEntry, *m_csFace, data);

         this->dispatchToStrategy(*pitEntry,
             [&] (fw::Strategy& strategy) { strategy.beforeSatisfyInterest(pitEntry, *m_csFace, data); });
         inRecord->setInPreviousRemedy(true);
         this->onOutgoingData(data,inFace);
         return;
       }
       
    }
    else
    {
      //Not an exclude version of the duplicate nonce
      // goto Interest loop pipeline
      this->onInterestLoop(inFace, interest);
      return;
    }
  }

  // cancel unsatisfy & straggler timer
  this->cancelUnsatisfyAndStragglerTimer(*pitEntry);

  //const pit::InRecordCollection& inRecords = pitEntry->getInRecords();
  //bool isPending = inRecords.begin() != inRecords.end();

  //TO-DO: isPending is now if the pitEntry doesn't have data or isAwaitingRemedy()
  //if NACK => entry was alrewady deleted
  bool isPending = pitEntry->isAwaitingRemedy() || !(pitEntry->hasRespondedData());

  //cout << "PitEntry is currently pending: " << isPending << endl;

  //if I am awaiting a remedy or I have not received an Answer => I am pending.

  if (!isPending) {
    //found CS data should be what was previously responded
    if (m_csFromNdnSim == nullptr) {
      m_cs.find(goodInterest,
                bind(&Forwarder::onContentStoreHit, this, ref(inFace), pitEntry, _1, _2),
                bind(&Forwarder::onContentStoreMiss, this, ref(inFace), pitEntry, _1));
    }
    else {
      shared_ptr<Data> match = m_csFromNdnSim->Lookup(goodInterest.shared_from_this());
      if (match != nullptr) {
        this->onContentStoreHit(inFace, pitEntry, goodInterest, *match);
      }
      else {
        this->onContentStoreMiss(inFace, pitEntry, goodInterest);
      }
    }
  }
  else {
    this->onContentStoreMiss(inFace, pitEntry, goodInterest);
  }
}

void
Forwarder::onInterestLoop(Face& inFace, const Interest& interest)
{
  // if multi-access face, drop
  if (inFace.getLinkType() == ndn::nfd::LINK_TYPE_MULTI_ACCESS) {
    NFD_LOG_DEBUG("onInterestLoop face=" << inFace.getId() <<
                  " interest=" << interest.getName() <<
                  " drop");
    return;
  }

  NFD_LOG_DEBUG("onInterestLoop face=" << inFace.getId() <<
                " interest=" << interest.getName() <<
                " send-Nack-duplicate");

  // send Nack with reason=DUPLICATE
  // note: Don't enter outgoing Nack pipeline because it needs an in-record.
  lp::Nack nack(interest);
  nack.setReason(lp::NackReason::DUPLICATE);
  inFace.sendNack(nack);
}

void
Forwarder::onContentStoreMiss(const Face& inFace, const shared_ptr<pit::Entry>& pitEntry,
                              const Interest& interest)
{
  NFD_LOG_DEBUG("onContentStoreMiss interest=" << interest.getName());
  cout << "pursuing packet for :" << interest.toUri() << endl;
  //is currently "looping" since it's sending to the same outface and getting the same answer (going to feed exclude interest
  //when remedy triggered)
  //CAN'T BE DONE: if not exclude interest and is awaiting remedy, try face that is different from the original answer face

  // insert in-record
  pitEntry->insertOrUpdateInRecord(const_cast<Face&>(inFace), interest);

  // set PIT unsatisfy timer
  this->setUnsatisfyTimer(pitEntry);

  // has NextHopFaceId?
  shared_ptr<lp::NextHopFaceIdTag> nextHopTag = interest.getTag<lp::NextHopFaceIdTag>();
  if (nextHopTag != nullptr) {
    // chosen NextHop face exists?
    Face* nextHopFace = m_faceTable.get(*nextHopTag);
    if (nextHopFace != nullptr) {
      NFD_LOG_DEBUG("onContentStoreMiss interest=" << interest.getName() << " nexthop-faceid=" << nextHopFace->getId());
      // go to outgoing Interest pipeline
      // scope control is unnecessary, because privileged app explicitly wants to forward
      this->onOutgoingInterest(pitEntry, *nextHopFace, interest);
    }
    return;
  }

  // dispatch to strategy: after incoming Interest
  this->dispatchToStrategy(*pitEntry,
    [&] (fw::Strategy& strategy) { strategy.afterReceiveInterest(inFace, interest, pitEntry); });
}

void
Forwarder::onContentStoreHit(const Face& inFace, const shared_ptr<pit::Entry>& pitEntry,
                             const Interest& interest, const Data& data)
{

  //To-Do: Check that the data being used matches what was recorded with the pit entry
  if(pitEntry->hasRespondedData())
  {
     if(data != pitEntry->getRespondedData() && !pitEntry->isAwaitingRemedy())
     {
        cout << "Bad hit! " << data.getName() << " doesn't match " << pitEntry->getRespondedData().getName() << endl;
        NFD_LOG_DEBUG("Bad hit! " << data.getName() << " doesn't match " << pitEntry->getRespondedData().getName());
        return;
     }
  }
  NFD_LOG_DEBUG("onContentStoreHit interest=" << interest.getName());

   beforeSatisfyInterest(*pitEntry, *m_csFace, data);
   this->dispatchToStrategy(*pitEntry,
   [&] (fw::Strategy& strategy) { strategy.beforeSatisfyInterest(pitEntry, *m_csFace, data); });

   data.setTag(make_shared<lp::IncomingFaceIdTag>(face::FACEID_CONTENT_STORE));
   // XXX should we lookup PIT for other Interests that also match csMatch?

   //Interest fulfilled by cached data
   pit::InRecordCollection::iterator inRecord = pitEntry->getInRecord(inFace);
   inRecord->setInPreviousRemedy(true);

   // set PIT straggler timer
   this->setStragglerTimer(pitEntry, true, data.getFreshnessPeriod());
   this->setAwaitingResponseTimer(pitEntry, true, data.getFreshnessPeriod());

   // goto outgoing Data pipeline
   this->onOutgoingData(data, *const_pointer_cast<Face>(inFace.shared_from_this()));
}

void
Forwarder::onOutgoingInterest(const shared_ptr<pit::Entry>& pitEntry, Face& outFace, const Interest& interest)
{
  NFD_LOG_DEBUG("onOutgoingInterest face=" << outFace.getId() <<
                " interest=" << pitEntry->getName());
  cout << "Outgoing Interest face=" << outFace.getId() << " interest=" << interest.toUri() << endl;

  // insert out-record
  pitEntry->insertOrUpdateOutRecord(outFace, interest);

  // send Interest
  outFace.sendInterest(interest);
  ++m_counters.nOutInterests;
}

void
Forwarder::onInterestReject(const shared_ptr<pit::Entry>& pitEntry)
{
  if (fw::hasPendingOutRecords(*pitEntry)) {
    NFD_LOG_ERROR("onInterestReject interest=" << pitEntry->getName() <<
                  " cannot reject forwarded Interest");
    return;
  }
  NFD_LOG_DEBUG("onInterestReject interest=" << pitEntry->getName());

  // cancel unsatisfy & straggler timer
  this->cancelUnsatisfyAndStragglerTimer(*pitEntry);

  // set PIT straggler timer
  this->setStragglerTimer(pitEntry, false);
}

//on done awaiting response (this should only be called if I was waiting for an Exclude
//but none were received and timer expired) => isSatisfied
void Forwarder::onDoneAwaitingResponse(const shared_ptr<pit::Entry>& pitEntry)
{
   //delete entry
   this->onInterestFinalize(pitEntry, true);
}

void
Forwarder::onInterestUnsatisfied(const shared_ptr<pit::Entry>& pitEntry)
{
  NFD_LOG_DEBUG("onInterestUnsatisfied interest=" << pitEntry->getName());

  // invoke PIT unsatisfied callback
  beforeExpirePendingInterest(*pitEntry);
  this->dispatchToStrategy(*pitEntry,
    [&] (fw::Strategy& strategy) { strategy.beforeExpirePendingInterest(pitEntry); });

  // goto Interest Finalize pipeline
  this->onInterestFinalize(pitEntry, false);
  this->cancelAwaitingResponseTimer(*pitEntry);

  //erase in the case of NACK/unsatisfied
  m_pit.erase(pitEntry.get());
}

void
Forwarder::onInterestFinalize(const shared_ptr<pit::Entry>& pitEntry, bool isSatisfied,
                              time::milliseconds dataFreshnessPeriod)
{
  NFD_LOG_DEBUG("onInterestFinalize interest=" << pitEntry->getName() <<
                (isSatisfied ? " satisfied" : " unsatisfied"));

  // Dead Nonce List insert if necessary
  this->insertDeadNonceList(*pitEntry, isSatisfied, dataFreshnessPeriod, 0);

  // PIT delete
  this->cancelUnsatisfyAndStragglerTimer(*pitEntry);
  //m_pit.erase(pitEntry.get());
}

void
Forwarder::onIncomingData(Face& inFace, const Data& data)
{
  // receive Data
  NFD_LOG_DEBUG("onIncomingData face=" << inFace.getId() << " data=" << data.getName());
  data.setTag(make_shared<lp::IncomingFaceIdTag>(inFace.getId()));
  ++m_counters.nInData;

  // /localhost scope control
  bool isViolatingLocalhost = inFace.getScope() == ndn::nfd::FACE_SCOPE_NON_LOCAL &&
                              scope_prefix::LOCALHOST.isPrefixOf(data.getName());
  if (isViolatingLocalhost) {
    NFD_LOG_DEBUG("onIncomingData face=" << inFace.getId() <<
                  " data=" << data.getName() << " violates /localhost");
    // (drop)
    return;
  }

  // PIT match
  pit::DataMatchResult pitMatches = m_pit.findAllDataMatches(data);
  if (pitMatches.begin() == pitMatches.end()) {
    // goto Data unsolicited pipeline
    this->onDataUnsolicited(inFace, data);
    return;
  }

  shared_ptr<Data> dataCopyWithoutTag = make_shared<Data>(data);
  dataCopyWithoutTag->removeTag<lp::HopCountTag>();

  // CS insert
  if (m_csFromNdnSim == nullptr)
    m_cs.insert(*dataCopyWithoutTag);
  else
    m_csFromNdnSim->Add(dataCopyWithoutTag);

  std::set<Face*> pendingDownstreams;
  // foreach PitEntry
  auto now = time::steady_clock::now();

  for (const shared_ptr<pit::Entry>& pitEntry : pitMatches) {
    NFD_LOG_DEBUG("onIncomingData matching=" << pitEntry->getName());
    cout << "onIncomingData matching=" << pitEntry->getName() << "with name " << data.getName() << endl;

    if(pitEntry->isAwaitingRemedy())
    {
       //if the matched pitEntry is awaiting a remedy have to do a bit of cache cleaning
       cout << "PitEntry " << pitEntry->getName() << " is awaiting remedy" << endl;
       //TO-DO: seems that this is generating too many false positives??? (even on the right data it's not executing
       //the delete)
       if(pitEntry->getRespondedData() == data)
       {
         //ignore this pitmatch...
         //duplicate of the original bad data => don't want this one...
         cout << "duplicate data received" << endl;
         continue;
       }
       else
       {
          pitEntry->setAwaitingRemedy(false);
          Data lastRespondedData = pitEntry->getRespondedData();
          auto outInRecord = pitEntry->getInRecord(inFace);

          cout<<"removing data of " << lastRespondedData.getName();

          bool successfulDelete = m_cs.deleteEntry(outInRecord->getInterest(), lastRespondedData);
          if(!successfulDelete)
          {
            cout << "No such entry was found" << endl;
            NFD_LOG_DEBUG("Previously responded data entry was not found");
          }
       }
    }
    
    //store the record
    pitEntry->setRespondedData(data);
    //cout << "responded data recorded" << endl;

    // cancel unsatisfy & straggler timer
    this->cancelUnsatisfyAndStragglerTimer(*pitEntry);

    // remember pending downstreams
    for (const pit::InRecord& inRecord : pitEntry->getInRecords()) {
      if (inRecord.getExpiry() > now) {
        pendingDownstreams.insert(&inRecord.getFace());
      }
    }
    //cout << "Finished creating list of pending downstreams" << endl;

    for (Face* pendingDownstream : pendingDownstreams) {
       pit::InRecordCollection::iterator inRecord = pitEntry->getInRecord(*pendingDownstream);
       inRecord->setInPreviousRemedy(true);
       inRecord->setReceivedExclude(false);
    }
    //cout << "Set in prev remedy to true" << endl;

    // invoke PIT satisfy callback
    beforeSatisfyInterest(*pitEntry, inFace, data);
    this->dispatchToStrategy(*pitEntry,
      [&] (fw::Strategy& strategy) { strategy.beforeSatisfyInterest(pitEntry, inFace, data); });

    // Dead Nonce List insert if necessary (for out-record of inFace)
    this->insertDeadNonceList(*pitEntry, true, data.getFreshnessPeriod(), &inFace);

    // mark PIT satisfied
    //pitEntry->clearInRecords();
    pitEntry->deleteOutRecord(inFace);
    //cout << "pit entry deleted out record" << endl;

    // set PIT straggler timer
    this->setStragglerTimer(pitEntry, true, data.getFreshnessPeriod());

    //start timer for excludes
    this->setAwaitingResponseTimer(pitEntry, true, data.getFreshnessPeriod());
  }

  // foreach pending downstream
  for (Face* pendingDownstream : pendingDownstreams) {
    if (pendingDownstream == &inFace) {
      continue;
    }
    // goto outgoing Data pipeline
    this->onOutgoingData(data, *pendingDownstream);
  }
}

void
Forwarder::onDataUnsolicited(Face& inFace, const Data& data)
{
  // accept to cache?
  fw::UnsolicitedDataDecision decision = m_unsolicitedDataPolicy->decide(inFace, data);
  if (decision == fw::UnsolicitedDataDecision::CACHE) {
    // CS insert
    if (m_csFromNdnSim == nullptr)
      m_cs.insert(data, true);
    else
      m_csFromNdnSim->Add(data.shared_from_this());
  }

  NFD_LOG_DEBUG("onDataUnsolicited face=" << inFace.getId() <<
                " data=" << data.getName() <<
                " decision=" << decision);
}

void
Forwarder::onOutgoingData(const Data& data, Face& outFace)
{
  cout << "sending Data " << data.getName() << endl;
  if (outFace.getId() == face::INVALID_FACEID) {
    NFD_LOG_WARN("onOutgoingData face=invalid data=" << data.getName());
    return;
  }
  NFD_LOG_DEBUG("onOutgoingData face=" << outFace.getId() << " data=" << data.getName());

  // /localhost scope control
  bool isViolatingLocalhost = outFace.getScope() == ndn::nfd::FACE_SCOPE_NON_LOCAL &&
                              scope_prefix::LOCALHOST.isPrefixOf(data.getName());
  if (isViolatingLocalhost) {
    NFD_LOG_DEBUG("onOutgoingData face=" << outFace.getId() <<
                  " data=" << data.getName() << " violates /localhost");
    // (drop)
    return;
  }

  // TODO traffic manager

  // send Data
  outFace.sendData(data);
  ++m_counters.nOutData;
}

void
Forwarder::onIncomingNack(Face& inFace, const lp::Nack& nack)
{
  // receive Nack
  nack.setTag(make_shared<lp::IncomingFaceIdTag>(inFace.getId()));
  ++m_counters.nInNacks;

  // if multi-access face, drop
  if (inFace.getLinkType() == ndn::nfd::LINK_TYPE_MULTI_ACCESS) {
    NFD_LOG_DEBUG("onIncomingNack face=" << inFace.getId() <<
                  " nack=" << nack.getInterest().getName() <<
                  "~" << nack.getReason() << " face-is-multi-access");
    return;
  }

  // PIT match
  shared_ptr<pit::Entry> pitEntry = m_pit.find(nack.getInterest());
  // if no PIT entry found, drop
  if (pitEntry == nullptr) {
    NFD_LOG_DEBUG("onIncomingNack face=" << inFace.getId() <<
                  " nack=" << nack.getInterest().getName() <<
                  "~" << nack.getReason() << " no-PIT-entry");
    return;
  }

  // has out-record?
  pit::OutRecordCollection::iterator outRecord = pitEntry->getOutRecord(inFace);
  // if no out-record found, drop
  if (outRecord == pitEntry->out_end()) {
    NFD_LOG_DEBUG("onIncomingNack face=" << inFace.getId() <<
                  " nack=" << nack.getInterest().getName() <<
                  "~" << nack.getReason() << " no-out-record");
    return;
  }

  // if out-record has different Nonce, drop
  if (nack.getInterest().getNonce() != outRecord->getLastNonce()) {
    NFD_LOG_DEBUG("onIncomingNack face=" << inFace.getId() <<
                  " nack=" << nack.getInterest().getName() <<
                  "~" << nack.getReason() << " wrong-Nonce " <<
                  nack.getInterest().getNonce() << "!=" << outRecord->getLastNonce());
    return;
  }

  NFD_LOG_DEBUG("onIncomingNack face=" << inFace.getId() <<
                " nack=" << nack.getInterest().getName() <<
                "~" << nack.getReason() << " OK");

  // record Nack on out-record
  outRecord->setIncomingNack(nack);

  // trigger strategy: after receive NACK
  this->dispatchToStrategy(*pitEntry,
    [&] (fw::Strategy& strategy) { strategy.afterReceiveNack(inFace, nack, pitEntry); });
}

void
Forwarder::onOutgoingNack(const shared_ptr<pit::Entry>& pitEntry, const Face& outFace,
                          const lp::NackHeader& nack)
{
  if (outFace.getId() == face::INVALID_FACEID) {
    NFD_LOG_WARN("onOutgoingNack face=invalid" <<
                  " nack=" << pitEntry->getInterest().getName() <<
                  "~" << nack.getReason() << " no-in-record");
    return;
  }

  // has in-record?
  pit::InRecordCollection::iterator inRecord = pitEntry->getInRecord(outFace);

  // if no in-record found, drop
  if (inRecord == pitEntry->in_end()) {
    NFD_LOG_DEBUG("onOutgoingNack face=" << outFace.getId() <<
                  " nack=" << pitEntry->getInterest().getName() <<
                  "~" << nack.getReason() << " no-in-record");
    return;
  }

  // if multi-access face, drop
  if (outFace.getLinkType() == ndn::nfd::LINK_TYPE_MULTI_ACCESS) {
    NFD_LOG_DEBUG("onOutgoingNack face=" << outFace.getId() <<
                  " nack=" << pitEntry->getInterest().getName() <<
                  "~" << nack.getReason() << " face-is-multi-access");
    return;
  }

  NFD_LOG_DEBUG("onOutgoingNack face=" << outFace.getId() <<
                " nack=" << pitEntry->getInterest().getName() <<
                "~" << nack.getReason() << " OK");

  // create Nack packet with the Interest from in-record
  lp::Nack nackPkt(inRecord->getInterest());
  nackPkt.setHeader(nack);

  // erase in-record
  pitEntry->deleteInRecord(outFace);

  // send Nack on face
  const_cast<Face&>(outFace).sendNack(nackPkt);
  ++m_counters.nOutNacks;
}

static inline bool
compare_InRecord_expiry(const pit::InRecord& a, const pit::InRecord& b)
{
  return a.getExpiry() < b.getExpiry();
}

void
Forwarder::setUnsatisfyTimer(const shared_ptr<pit::Entry>& pitEntry)
{
  pit::InRecordCollection::iterator lastExpiring =
    std::max_element(pitEntry->in_begin(), pitEntry->in_end(), &compare_InRecord_expiry);

  time::steady_clock::TimePoint lastExpiry = lastExpiring->getExpiry();
  time::nanoseconds lastExpiryFromNow = lastExpiry - time::steady_clock::now();
  if (lastExpiryFromNow <= time::seconds::zero()) {
    // TODO all in-records are already expired; will this happen?
  }

  scheduler::cancel(pitEntry->m_unsatisfyTimer);
  pitEntry->m_unsatisfyTimer = scheduler::schedule(lastExpiryFromNow,
    bind(&Forwarder::onInterestUnsatisfied, this, pitEntry));
}

void
Forwarder::setAwaitingResponseTimer(const shared_ptr<pit::Entry>& pitEntry, bool isSatisfied,
                    time::milliseconds dataFreshnessPeriod)
{
   //I want to get the face ID per pit entry and get the one who is the furthest away...
   //for each element, get the inFace ID. From Face ID, get FIB entry
   //from fib entry call measurements => get average response time.
   //Get max average response time else, default will be interest lifetime

   time::nanoseconds expiryTime(20000000000); 
   scheduler::cancel(pitEntry->m_awaitingResponseTimer);
   pitEntry->m_awaitingResponseTimer = scheduler::schedule(expiryTime, bind(&Forwarder::onARTExpire, this, pitEntry, dataFreshnessPeriod));
   //cout << "AR Timer set for " << pitEntry << "." << endl;
}

void
Forwarder::onARTExpire(const shared_ptr<pit::Entry>& pitEntry, time::milliseconds dataFreshnessPeriod)
{
   NFD_LOG_DEBUG("ARTimer Expired");
   cout << "AR Timer for " << pitEntry << "has expired." << endl; 
   //nullify all the nonces as needed
   this->insertDeadNonceList(*pitEntry, true, dataFreshnessPeriod, 0);

   //cancel the awaiting response timer
   this->cancelAwaitingResponseTimer(*pitEntry);
   this->cancelUnsatisfyAndStragglerTimer(*pitEntry);

   //delete the pit entry
   m_pit.erase(pitEntry.get());
}

//might not be needed??? Though might be called when remedy started
void
Forwarder::cancelAwaitingResponseTimer(pit::Entry& pitEntry)
{
  NFD_LOG_DEBUG("ARTimer canceled");
  scheduler::cancel(pitEntry.m_awaitingResponseTimer);
}

void
Forwarder::setStragglerTimer(const shared_ptr<pit::Entry>& pitEntry, bool isSatisfied,
                             time::milliseconds dataFreshnessPeriod)
{
  time::nanoseconds stragglerTime = time::milliseconds(100);

  scheduler::cancel(pitEntry->m_stragglerTimer);
  pitEntry->m_stragglerTimer = scheduler::schedule(stragglerTime,
    bind(&Forwarder::onInterestFinalize, this, pitEntry, isSatisfied, dataFreshnessPeriod));
}

void
Forwarder::cancelUnsatisfyAndStragglerTimer(pit::Entry& pitEntry)
{
  scheduler::cancel(pitEntry.m_unsatisfyTimer);
  scheduler::cancel(pitEntry.m_stragglerTimer);
}

static inline void
insertNonceToDnl(DeadNonceList& dnl, const pit::Entry& pitEntry,
                 const pit::OutRecord& outRecord)
{
  dnl.add(pitEntry.getName(), outRecord.getLastNonce());
}

void
Forwarder::insertDeadNonceList(pit::Entry& pitEntry, bool isSatisfied,
                               time::milliseconds dataFreshnessPeriod, Face* upstream)
{
  // need Dead Nonce List insert?
  bool needDnl = false;
  if (isSatisfied) {
    bool hasFreshnessPeriod = dataFreshnessPeriod >= time::milliseconds::zero();
    // Data never becomes stale if it doesn't have FreshnessPeriod field
    needDnl = static_cast<bool>(pitEntry.getInterest().getMustBeFresh()) &&
              (hasFreshnessPeriod && dataFreshnessPeriod < m_deadNonceList.getLifetime());
  }
  else {
    needDnl = true;
  }

  if (!needDnl) {
    return;
  }

  // Dead Nonce List insert
  if (upstream == 0) {
    // insert all outgoing Nonces
    const pit::OutRecordCollection& outRecords = pitEntry.getOutRecords();
    std::for_each(outRecords.begin(), outRecords.end(),
                  bind(&insertNonceToDnl, ref(m_deadNonceList), cref(pitEntry), _1));
  }
  else {
    // insert outgoing Nonce of a specific face
    pit::OutRecordCollection::iterator outRecord = pitEntry.getOutRecord(*upstream);
    if (outRecord != pitEntry.getOutRecords().end()) {
      m_deadNonceList.add(pitEntry.getName(), outRecord->getLastNonce());
    }
  }
}

} // namespace nfd
