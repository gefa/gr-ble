/* -*- c++ -*- */

#define BLE_API

%include "gnuradio.i"           // the common stuff

//load generated python docstrings
%include "ble_swig_doc.i"

%{
#include "ble/preamble.h"
#include "ble/whiten.h"
#include "ble/packet_sink.h"
%}

%include "ble/preamble.h"
GR_SWIG_BLOCK_MAGIC2(ble, preamble);
%include "ble/whiten.h"
GR_SWIG_BLOCK_MAGIC2(ble, whiten);
%include "ble/packet_sink.h"
GR_SWIG_BLOCK_MAGIC2(ble, packet_sink);
