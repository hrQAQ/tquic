

use crate::frame::Frame;
use bytes::Bytes;
#[derive(Debug, Clone)]
pub struct DatagramMap
{
    ///发送datagram帧时，存储各个dadagram帧数据
    out_queue:VecDeque<Frame::Datagram>,
    out_total_size:u64,
    out_max_size:u64,
    ///接受datagram帧时，存储各个datagram帧的数据
    in_queue:VecDeque<Frame::Datagram>,
    in_total_size:u64,    
    in_max_size:u64,
    max_datagram_frame_size:u64,

}
#[derive(Debug)]
impl DatagramMap 
{
    pub fn new(max_datagram_frame_size:u64)->Self{
        Self{
            out_queue:Vec::new(),
            out_total_size:0,///默认不超过1MB
            out_max_size:1024*1024,
            in_queue:Vec::new(),
            in_total_size:0,
            in_max_size:1024*1024,
            max_datagram_frame_size:max_datagram_frame_size,
        }
    }
    pub fn is_enable(&self)->bool//验证是否可发送
    {
        if self.max_datagram_frame_size>0
        {
            return true
        }
        else{
            return false
        }
    }
    pub fn change_mdfs(& mut self,new_size:u32)//修改
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
    pub fn send_datagram(&mut self,data: Bytes,drop_if:bool)->Result<()>//从本地向发送队列添加一个帧
    {
        if !self.is_enable()
        {
            return Err();///略去错误处理
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
                return Err();///略去错误处理
            }
        }

        self.out_queue.push_back(
            Datagram{
                data.clone().to_vec()
            });
        self.out_total_size+=data.len();
        return Ok(());
    }
    pub fn outcome_datagram(&mut self,max_payload_size: usize)->Option<Frame>{//向对方从发送队列发送一个帧
        while let Some(data)=self.out_queue.get(0)
        {
            if data.length<max_payload_size && data.data.len()<max_payload_size
            {
                let data =self.out_queue.pop_front().unwrap();
                self.out_total_size-=data.data.len();
                return Some(Frame::datagram{data.has_length,data.length,data.data});
            }else{
                ///丢弃
                let data =self.out_queue.pop_front().unwrap();
                self.out_total_size-=data.data.len();
            }
        }
        None
    }

    pub fn income_datagram(&mut self, data:Bytes)->Result<()>{///从对方向接受队列添加一个帧
        if !self.is_enable()
        {
            return Err();///略去错误处理
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
    pub fn get_datagram(&mut self)->Option<Frame::datagram>///本地从接受队列获得一个帧
    {
        if let Some(data)=self.in_queue.pop_front(){
            self.in_total_size-=data.len();
            Some(data)
        }else{
            None
        }
    }

    pub fn send_available_space(&self)->usize//发送队列的可用空间
    {
        self.out_max_size.saturating_sub(self.out_total_size)
    }
    pub fn recv_available_space(&self)->usize//接受队列的可用空间
    {
        self.in_max_size.saturating_sub(self.in_total_size)
    }
    pub fn if_out_empty(&self)->bool///发送队列是否为空
    {
        self.out_queue.is_empty();
    }
    pub fn if_in_empty(&self)->bool///接受队列是否为空
    {
        self.in_queue.is_empty();
    }
}