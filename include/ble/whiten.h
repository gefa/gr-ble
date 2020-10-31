/* -*- c++ -*- */
/*
 * Copyright 2020 gr-ble author.
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

#ifndef INCLUDED_BLE_WHITEN_H
#define INCLUDED_BLE_WHITEN_H

#include <ble/api.h>
#include <gnuradio/block.h>

namespace gr {
  namespace ble {

    /*!
     * \brief <+description of block+>
     * \ingroup ble
     *
     */
    class BLE_API whiten : virtual public gr::block
    {
     public:
      typedef boost::shared_ptr<whiten> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of ble::whiten.
       *
       * To avoid accidental use of raw pointers, ble::whiten's
       * constructor is in a private implementation
       * class. ble::whiten::make is the public interface for
       * creating new instances.
       */
      static sptr make(int chan_nbr);
    };

  } // namespace ble
} // namespace gr

#endif /* INCLUDED_BLE_WHITEN_H */

