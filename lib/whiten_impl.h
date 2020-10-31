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

#ifndef INCLUDED_BLE_WHITEN_IMPL_H
#define INCLUDED_BLE_WHITEN_IMPL_H

#include <ble/whiten.h>

namespace gr {
  namespace ble {

    class whiten_impl : public whiten
    {
     private:
      char buf[256];
      int i_chan_nbr = 37;
      unsigned char whitening_reg;
      unsigned char init_whitening_reg;

     public:
      whiten_impl(int chan_nbr);
      ~whiten_impl();

      // Where all the action really happens
     unsigned char swap8bits(unsigned char a);
     unsigned char byte_whitening(unsigned char data);
     void packet_whitening(char * data,int length);
     void make_frame (pmt::pmt_t msg);

    };

  } // namespace ble
} // namespace gr

#endif /* INCLUDED_BLE_WHITEN_IMPL_H */

