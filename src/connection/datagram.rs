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
use crate::frame;
use crate::frame::Frame;
use bytes::Bytes;
use crate::Error;
#[derive(Debug, Clone)]
pub struct DatagramMap
{
    /// Sender states
    out_queue:VecDeque<Frame>,
    out_total_size:u64,
    out_max_size:u64,
    /// Receiver states
    in_queue:VecDeque<Frame>,
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
            out_total_size:0,
            out_max_size:1024*1024,
            in_queue:VecDeque::new(),
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
        self.peer_max_data_frame_size=new_size;
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
    //应用层向发送缓冲区存入一个datagram
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
                    if let Some(old_data)=self.out_queue.pop_front()
                    {
                        self.out_total_size-=old_data.data.len();
                    }else{
                        break;
                    }
                }
            }else{
                return Err(Error::ErrorDatagramTest);
            }
        }

        self.out_queue.push_back(
            Frame::Datagram{
                length:data.len(),
                data:data.clone(),
            });
        self.out_total_size +=data.len();
        return Ok(());
    }
    //从发送队列取出一个帧发送
    pub fn outcome_datagram(&mut self, max_payload_size:usize)->Option<Frame>{

        let Some(front_data) = self.out_queue.front() else {
            return None; // 队列为空，无数据可发
        };
        if front_data.length>max_payload_size 
        {
            return  None;
        }else{
            let data=self.out_queue.pop_front().unwrap();
            self.out_total_size-=data.length;
            return Some(Frame::Datagram { length: data.length, data: data.data });
        }

    }
    //从connection接受一个datagram
    pub fn incoming_datagram(&mut self, data:Bytes)->Result<()>{
        if !self.local_is_enable()
        {
            return Err(Error::ErrorDatagramTest);
        }
        if data.len()>self.in_max_size
        {
            return Err(Error::ErrorDatagramTest);
        }
        if data.len()>self.local_max_datagram_frame_size{
            return Err(Error::ErrorDatagramTest);
        }
        while self.in_total_size+data.len()>self.in_max_size{
            if let Some(old_data)=self.in_queue.pop_front()
            {
                self.in_total_size-=old_data.data.len();
            }else{
                break;
            }
        }
        self.in_queue.push_back(Frame::Datagram{length:data.len() ,data:data.clone()});
        self.in_total_size+=data.len();
        Ok(())
    }
    //从接收队列取出一个帧给引用层
    pub fn get_datagram(&mut self)->Option<Bytes>
    {
        if let Some(data)=self.in_queue.pop_front(){
            self.in_total_size-=data.len();
            Some(data.data.clone)
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
