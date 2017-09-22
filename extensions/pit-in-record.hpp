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

#ifndef NFD_DAEMON_TABLE_PIT_IN_RECORD_HPP
#define NFD_DAEMON_TABLE_PIT_IN_RECORD_HPP

#include "pit-face-record.hpp"

namespace nfd {
namespace pit {

/** \brief contains information about an Interest from an incoming face
 */
class InRecord : public FaceRecord
{
public:
  explicit
  InRecord(Face& face);

  void
  update(const Interest& interest);

  const Interest&
  getInterest() const;

  void setReceivedExclude(bool b)
  {
     m_receivedExclude = b;
  }

  bool getReceivedExclude()
  {
     return m_receivedExclude;
  }

  bool getInPreviousRemedy() const
  {
     return m_inPrevRemedy;
  }

  void setInPreviousRemedy(bool b)
  {
      m_inPrevRemedy = b;
  }

private:
  shared_ptr<const Interest> m_interest;
  bool m_receivedExclude;
  bool m_inPrevRemedy;
};

inline const Interest&
InRecord::getInterest() const
{
  BOOST_ASSERT(static_cast<bool>(m_interest));
  return *m_interest;
}

} // namespace pit
} // namespace nfd

#endif // NFD_DAEMON_TABLE_PIT_IN_RECORD_HPP
