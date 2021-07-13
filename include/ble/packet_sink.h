/* -*- c++ -*- */
/*
 * Copyright 2013 Airbus DS CyberSecurity.
 * Authors: Jean-Michel Picod, Arnaud Lebrun, Jonathan Christofer Demay
 *
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this software; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#ifndef INCLUDED_BLE_PACKET_SINK_H
#define INCLUDED_BLE_PACKET_SINK_H

#include <ble/api.h>
#include <gnuradio/block.h>

namespace gr {
  namespace ble {

    /*!
     * \brief <+description of block+>
     * \ingroup ble
     *
     */
    class BLE_API packet_sink : virtual public gr::block
    {
     public:
      typedef boost::shared_ptr<packet_sink> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of ble::packet_sink.
       *
       * To avoid accidental use of raw pointers, ble::packet_sink's
       * constructor is in a private implementation
       * class. ble::packet_sink::make is the public interface for
       * creating new instances.
       */
      static sptr make(int i_chan_nbr);
    };

  } // namespace ble
} // namespace gr

#endif /* INCLUDED_BLE_PACKET_SINK_H */

