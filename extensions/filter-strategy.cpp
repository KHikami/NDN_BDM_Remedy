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

#include "filter-strategy.hpp"
#include <stdlib.h>  
#include "algorithm.hpp"

namespace nfd {
namespace fw {

using namespace std;

const Name FilterStrategy::STRATEGY_NAME("ndn:/localhost/nfd/strategy/filter/%FD%01");
NFD_REGISTER_STRATEGY(FilterStrategy);

FilterStrategy::FilterStrategy(Forwarder& forwarder, const Name& name)
  : Strategy(forwarder, name)
{
}

void
FilterStrategy::onDuplicateBadDataReceived(const Face& inFace)
{
   cout << "Duplicate bad data received on inFace " << inFace.getId() << endl;
   filterCountMap[inFace.getId()].numOfBadResponses++;
   cout << "updated bad data count to " << filterCountMap[inFace.getId()].numOfBadResponses << endl;
}

void
FilterStrategy::afterReceiveInterest(const Face& inFace, const Interest& interest,
                                        const shared_ptr<pit::Entry>& pitEntry)
{
  //upon receiving interest:
  //   keep count of how many times I had to send a correction packet down this path
  //   If canForwardExclude true => add to number of exclude sent
  //   If canForwardExclude false => add to number of okay sent
  //   Forward first to the ones I haven't tried before (after counting num of bad...)? (not too sure if this is possible..)

  const fib::Entry& fibEntry = this->lookupFib(*pitEntry);
  const fib::NextHopList& nexthops = fibEntry.getNextHops();
  bool hasExclude = interest.toUri().find("ndn.Exclude")!= std::string::npos;

  for (fib::NextHopList::const_iterator it = nexthops.begin(); it != nexthops.end(); ++it) {
    Face& outFace = it->getFace();

    if (!wouldViolateScope(inFace, interest, outFace) &&
        canForwardToLegacy(*pitEntry, outFace)) {

      if(filterCountMap.count(outFace.getId()) == 0)
      {
         //If I have not sent anything on this face has never been asked to send before, add new entry for face
         FilterCount tempEntry = {(uint16_t) 0, (uint16_t) 1};
         filterCountMap[outFace.getId()] = tempEntry;
         cout << "Face Counter: " << outFace.getId() << " Bad Count: " << tempEntry.numOfBadResponses << " Used Count: " << tempEntry.totalNumOfResponses << endl;
      }
      else
      {
         //this face has been used before...
         FilterCount currCounter = filterCountMap[outFace.getId()];
         //check if this record is a good one.
         bool faceBadRecord = (double(currCounter.numOfBadResponses)/double(currCounter.totalNumOfResponses) >= validPathThresh);
         // && (currCounter.totalNumOfResponses >= minNumOfSent)
         cout << "Face ID: " << outFace.getId() << " is bad? " << faceBadRecord << endl;
 
         if(faceBadRecord)
         {
            //skip over this face if it has a bad record
            continue;
         }
         else
         {
            filterCountMap[outFace.getId()].totalNumOfResponses++;
            cout << "Face ID: " << outFace.getId() << " Bad Count: " << filterCountMap[outFace.getId()].numOfBadResponses << " Used Count: " << filterCountMap[outFace.getId()].totalNumOfResponses << endl;
         }
      }

      if(hasExclude)
      {
        if(canForwardExclude(*pitEntry, outFace))
        {
          //cout << "sending interest " << interest.toUri() << "out on " << outFace.getId() << endl;
          this->sendInterest(pitEntry, outFace, interest);
        }
        else
        {
          shared_ptr<Interest> excludelessInterest = make_shared<Interest>();
          excludelessInterest->setName(interest.getName());
          excludelessInterest->setInterestLifetime(interest.getInterestLifetime());
          //creating a new nonce... (otherwise it ends up in duplicate nonce loop at the next hop location)
          excludelessInterest->setNonce(rand() % std::numeric_limits<uint32_t>::max());
          //cout << "sending interest " << excludelessInterest->toUri() << "out on " << outFace.getId() << endl;
          this->sendInterest(pitEntry, outFace, *excludelessInterest);
        }
      }
      else
      {
         this->sendInterest(pitEntry, outFace, interest);
      }
    }
  }

  if (!hasPendingOutRecords(*pitEntry)) {
    this->rejectPendingInterest(pitEntry);
  }
}

} // namespace fw
} // namespace nfd
