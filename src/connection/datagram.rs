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

use crate::frame::Frame;
use bytes::Bytes;
#[derive(Debug, Clone)]
pub struct DatagramMap
{
    /// Sender states
    out_queue:VecDeque<Frame::Datagram>,
    out_total_size:u64,
    out_max_size:u64,
    /// Receiver states
    in_queue:VecDeque<Frame::Datagram>,
    in_total_size:u64,    
    in_max_size:u64,
    local_max_datagram_frame_size:u64,
    peer_max_datagram_frame_size:u64,
}

impl DatagramMap 
{
    pub fn new(max_datagram_frame_size:u64)->Self{
        Self{
            out_queue:Vec::new(),
            out_total_size:0,
            out_max_size:1024*1024,
            in_queue:Vec::new(),
            in_total_size:0,
            in_max_size:1024*1024,
            max_datagram_frame_size:max_datagram_frame_size,
        }
    }
    pub fn is_enable(&self)->bool
    {
        if self.max_datagram_frame_size>0
        {
            return true
        }
        else{
            return false
        }
    }
    pub fn change_mdfs(& mut self,new_size:u32)
    {
        self.max_data_frame_size=new_size;
    }
    pub fn max_datagram_payload_size(&self,current_mtu:usize)->Option<usize>
    {
        if !self.is_enable()
        {
            return None;
        }
        let limit=self.max_datagram_frame_size;
        let frame_overhead=frame::MAX_DATAGRAM_OVERHEAD;
        let mtu_limit=current_mtu.saturating_sub(frame_overhead);
        let peer_limit=current_mtu.saturating_sub(frame_overhead);
        Some(mtu_limit.min(peer_limit))
    }
    pub fn send_datagram(&mut self,data: Bytes,drop_if:bool)->Result<()>
    {
        if !self.is_enable()
        {
            return Err();
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
                return Err();
            }
        }

        self.out_queue.push_back(
            Datagram{
                data.clone().to_vec()
            });
        self.out_total_size+=data.len();
        return Ok(());
    }
    pub fn outcome_datagram(&mut self,max_payload_size: usize)->Option<Frame>{
        while let Some(data)=self.out_queue.get(0)
        {
            if data.length<max_payload_size && data.data.len()<max_payload_size
            {
                let data =self.out_queue.pop_front().unwrap();
                self.out_total_size-=data.data.len();
                return Some(Frame::datagram{data.has_length,data.length,data.data});
            }else{
                let data =self.out_queue.pop_front().unwrap();
                self.out_total_size-=data.data.len();
            }
        }
        None
    }

    pub fn income_datagram(&mut self, data:Bytes)->Result<()>{
        if !self.is_enable()
        {
            return Err();
        }
        if let Some(max_size)=self.max_datagram_frame_size{
            if data.len()>max_size{
                return Err();
            }
        }

        while self.in_total_size+data.len()>self.in_max_size{
            if let Some(old_data)=self.in_queue.pop_front()
            {
                self.in_total_size-=old_data.data.len();
            }else{
                break;
            }
        }
        self.in_queue.push_back(Frame::datagram{has_length:true,length:data.len() as u64,data:data.clone().to_vec()});
        self.in_total_size+=data.len();
        Ok(())
    }
    pub fn get_datagram(&mut self)->Option<Frame::datagram>
    {
        if let Some(data)=self.in_queue.pop_front(){
            self.in_total_size-=data.len();
            Some(data)
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
