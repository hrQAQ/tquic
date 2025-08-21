// Copyright (c) 2023 The TQUIC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::VecDeque;
use crate::connection::datagram;
use crate::frame;
use crate::frame::Frame;
use bytes::Bytes;
use crate::Error;
#[derive(Debug, Clone)]

pub struct Datagramunit
{
    data:Bytes,
    length:Option<usize>,
    datagram_id:usize,
    /*
    the time arrive queue
    the priority
    the time of datagram become invalid
     */

}
impl Datagramunit {
    pub fn new (data:Bytes,length:Option<usize>,datagram_id:usize)->Self{
        Self { data:data, length: length, datagram_id: datagram_id }
    }
}
pub struct DatagramMap
{
    /// Sender states
    out_queue:VecDeque<Datagramunit>,
    index_out:usize,
    out_total_size:u64,
    out_max_size:u64,
    /// Receiver states
    in_queue:VecDeque<Datagramunit>,
    index_in:usize,
    in_total_size:u64,    
    in_max_size:u64,
    local_max_datagram_frame_size:u64,
    peer_max_datagram_frame_size:u64,

}
impl DatagramMap 
{
    pub fn new(peer_max_datagram_frame_size:u64,
        local_max_datagram_frame_size:u64)->Self{
        Self{
            out_queue:VecDeque::new(),
            index_out:0,
            out_total_size:0,
            out_max_size:1024*1024,
            in_queue:VecDeque::new(),
            index_in:0,
            in_total_size:0,
            in_max_size:1024*1024,
            local_max_datagram_frame_size,
            peer_max_datagram_frame_size,
        }
    }
    pub fn peer_is_enable(&self)->bool
    {
        if self.peer_max_datagram_frame_size>0
        {
            return true
        }
        else{
            return false
        }
    }

    pub fn local_is_enable(&self)->bool
    {
        if self.local_max_datagram_frame_size>0
        {
            return true
        }
        else{
            return false
        }
    }
    pub fn change_peer(& mut self,new_size:u64)
    {
        self.peer_max_datagram_frame_size=new_size;
    }
    pub fn change_local(& mut self,new_size:u64)
    {
        self.local_max_datagram_frame_size=new_size;
    }
    pub fn max_datagram_payload_size(&self,current_mtu:usize)->Option<usize>
    {
        if !self.peer_is_enable()
        {
            return None;
        }
        let limit=self.peer_max_datagram_frame_size;
        let frame_overhead=frame::MAX_DATAGRAM_OVERHEAD;
        let mtu_limit=current_mtu.saturating_sub(frame_overhead);
        let peer_limit=current_mtu.saturating_sub(frame_overhead);
        Some(mtu_limit.min(peer_limit))
    }
    //send a datagram from application to out_queue
    pub fn send_datagram(&mut self,data: Bytes,drop_if:bool)->Result<()>
    {
        if !self.peer_is_enable()
        {
            return Err(Error::ErrorDatagramTest);
        }
        if self.out_max_size<data.len()
        {
            return Err(Error::ErrorDatagramTest);//data > out_queue
        }
        if self.out_total_size+data.len()>self.out_max_size
        {
            if drop_if
            {
                while(self.out_total_size+data.len()>self.out_max_size)
                {
                    if let Some(datagramunit)=self.out_queue.pop_front()
                    {
                        self.out_total_size-=data.len();
                    }else{
                        break;
                    }
                }
            }else{
                return Err(Error::ErrorDatagramTest);
            }
        }

        self.out_queue.push_back(
            Datagramunit::new(data,Some(data.len()), self.index_out)
            );
        self.out_total_size +=data.len();
        self.index_out+=1;//change the index
        return Ok(());
    }
    //send a datagram from out_queue 
    pub fn outcome_datagram(&mut self, max_payload_size:usize)->Option<(Option<usize>,Bytes)>{

        let Some(datagramunit) = self.out_queue.front() else {
            return None; // out_queue is empty , no datagram to send 
        };
        if datagramunit.data.len()>max_payload_size 
        {
            return  None;
        }else{
            let datagramunit=self.out_queue.pop_front().unwrap();
            self.out_total_size-=datagramunit.data.len();
            return Some((datagramunit.data.length, datagramunit.data.clone()));
        }

    }
    //recv a datagram from connection to in_queue
    pub fn incoming_datagram(&mut self,length:Option<usize>, data:Bytes)->Result<usize>{
        if !self.local_is_enable()
        {
            return Err(Error:: ProtocolViolation);
        }
        if data.len()>self.in_max_size
        {
            return Err(Error:: DatagramFrameBeyondMemory);
        }
        if data.len()>self.local_max_datagram_frame_size{
            return Err(Error:: ProtocolViolation);
        }
        while self.in_total_size+data.len()>self.in_max_size{
            if let Some(datagramunit)=self.in_queue.pop_front()
            {
                self.in_total_size-=datagramunit.data.len();
            }else{
                break;
            }
        }
        self.in_queue.push_back(Datagramunit::new(data, length, self.index_in));
        self.in_total_size+=data.len();
        self.index_in+=1;
        Ok(self.index_in-1)
    }
    //从接收队列取出一个帧给引用层
    pub fn get_datagram(&mut self)->Option<(Option<usize>,Bytes)>
    {
        if let Some(datagramunit)=self.in_queue.pop_front(){
            self.in_total_size-=datagramunit.data.len();
            Some((datagramunit.length,datagramunit.data.clone()))
        }else{
            None
        }
    }

    pub fn send_available_space(&self)->usize
    {
        self.out_max_size.saturating_sub(self.out_total_size)
    }
    pub fn recv_available_space(&self)->usize
    {
        self.in_max_size.saturating_sub(self.in_total_size)
    }
    pub fn if_out_empty(&self)->bool
    {
        self.out_queue.is_empty();
    }
    pub fn if_in_empty(&self)->bool
    {
        self.in_queue.is_empty();
    }
}
