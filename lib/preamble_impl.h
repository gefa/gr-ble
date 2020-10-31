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

#ifndef INCLUDED_BLE_PREAMBLE_IMPL_H
#define INCLUDED_BLE_PREAMBLE_IMPL_H

#include <ble/preamble.h>

namespace gr {
  namespace ble {

    class preamble_impl : public preamble
    {
     private:
        //enought for a frame
        char preamble[256];

     public:
      preamble_impl();
      ~preamble_impl();

      // Where all the action really happens
      void make_frame (pmt::pmt_t msg);
      unsigned char swap8bits(unsigned char a);

    };

  } // namespace ble
} // namespace gr

#endif /* INCLUDED_BLE_PREAMBLE_IMPL_H */

