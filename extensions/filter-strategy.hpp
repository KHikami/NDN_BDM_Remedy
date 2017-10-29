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
 * 
 * Copied from Multicast Strategy as base. Modifying to act differently...
 */

#ifndef NFD_DAEMON_FW_FILTER_STRATEGY_HPP
#define NFD_DAEMON_FW_FILTER_STRATEGY_HPP

#include "strategy.hpp"
#include <stdlib.h> 
#include <map> 

namespace nfd {
namespace fw {

/** \brief a forwarding strategy that forwards Interest to all FIB nexthops
 */
class FilterStrategy : public Strategy
{
public:
  FilterStrategy(Forwarder& forwarder, const Name& name = STRATEGY_NAME);

  virtual void
  afterReceiveInterest(const Face& inFace, const Interest& interest,
                       const shared_ptr<pit::Entry>& pitEntry) override;

  virtual void
  onDuplicateBadDataReceived(const Face& inFace) override;

public:
  static const Name STRATEGY_NAME;

struct FilterCount{
    uint16_t numOfBadResponses;
    uint16_t totalNumOfResponses;
};

private:
  const double validPathThresh = 0.5;
  const uint8_t minNumOfSent = 3;

  //map should have as key faceID and the respective filter count 
  std::map<uint8_t, FilterCount> filterCountMap;

};

} // namespace fw
} // namespace nfd

#endif // NFD_DAEMON_FW_FILTER_STRATEGY_HPP
