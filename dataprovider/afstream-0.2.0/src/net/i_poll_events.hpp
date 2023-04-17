/*
    Copyright (c) 2007-2013 Contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/
 
#ifndef __ZMQ_I_POLL_EVENTS_HPP_INCLUDED__
#define __ZMQ_I_POLL_EVENTS_HPP_INCLUDED__
 
namespace afs_zmq
{
 
    // Virtual interface to be exposed by object that want to be notified
    // about events on file descriptors.
 
    struct i_poll_events
    {
        virtual ~i_poll_events () {}
 
        // Called by I/O thread when file descriptor is ready for reading.
        /*******************************************
        // qhuang: change return type from void to bool
        // all return values are FALSE, excect:
        //      stream_engine returns true to indicate termination 
        //      determined by recived wrap_item (I_FINISH)
        // see stream_engine.cpp for details
        *******************************************/
        virtual bool in_event () = 0;
 
        // Called by I/O thread when file descriptor is ready for writing.
        virtual bool out_event () = 0;
 
        // Called when timer expires.
        virtual void timer_event (int id_) = 0;
    };
 
}
 
#endif
