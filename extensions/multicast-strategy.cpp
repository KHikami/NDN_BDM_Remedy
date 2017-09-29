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

#include "multicast-strategy.hpp"
#include <stdlib.h>  
#include "algorithm.hpp"

namespace nfd {
namespace fw {

using namespace std;

const Name MulticastStrategy::STRATEGY_NAME("ndn:/localhost/nfd/strategy/multicast/%FD%01");
NFD_REGISTER_STRATEGY(MulticastStrategy);

MulticastStrategy::MulticastStrategy(Forwarder& forwarder, const Name& name)
  : Strategy(forwarder, name)
{
}

void
MulticastStrategy::afterReceiveInterest(const Face& inFace, const Interest& interest,
                                        const shared_ptr<pit::Entry>& pitEntry)
{
  const fib::Entry& fibEntry = this->lookupFib(*pitEntry);
  const fib::NextHopList& nexthops = fibEntry.getNextHops();
  
  bool hasExclude = interest.toUri().find("ndn.Exclude")!= std::string::npos;

  for (fib::NextHopList::const_iterator it = nexthops.begin(); it != nexthops.end(); ++it) {
    Face& outFace = it->getFace();
    //cout << "considering face " << outFace.getId() << endl;
    if (!wouldViolateScope(inFace, interest, outFace) &&
        canForwardToLegacy(*pitEntry, outFace)) {

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
