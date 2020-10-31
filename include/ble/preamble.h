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

#ifndef INCLUDED_BLE_PREAMBLE_H
#define INCLUDED_BLE_PREAMBLE_H

#include <ble/api.h>
#include <gnuradio/block.h>

namespace gr {
  namespace ble {

    /*!
     * \brief <+description of block+>
     * \ingroup ble
     *
     */
    class BLE_API preamble : virtual public gr::block
    {
     public:
      typedef boost::shared_ptr<preamble> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of ble::preamble.
       *
       * To avoid accidental use of raw pointers, ble::preamble's
       * constructor is in a private implementation
       * class. ble::preamble::make is the public interface for
       * creating new instances.
       */
      static sptr make();
    };

  } // namespace ble
} // namespace gr

#endif /* INCLUDED_BLE_PREAMBLE_H */

