#![allow(non_upper_case_globals)]

#[macro_use]
extern crate cpp;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate lazy_static;

use std::ffi::{CStr, CString};
use std::fmt;
use std::os::raw::c_char;
use std::ptr;
use std::str;
use std::slice;

cpp!{{
    #include <lldb/API/LLDB.h>
    using namespace lldb;
}}

pub type Address = u64;
pub type ThreadID = u64;
pub type BreakpointID = u32;
pub type UserID = u64;
pub type ProcessID = u64;

/////////////////////////////////////////////////////////////////////////////////////////////////////

fn debug_descr<CPP>(f: &mut fmt::Formatter, cpp: CPP) -> fmt::Result
where
    CPP: FnOnce(&mut SBStream) -> bool,
{
    let mut descr = SBStream::new();
    if cpp(&mut descr) {
        match str::from_utf8(descr.data()) {
            Ok(s) => f.write_str(s),
            Err(_) => Err(fmt::Error),
        }
    } else {
        Ok(())
    }
}

/////////////////////////////////////////////////////////////////////////////////////////////////////

struct SBIterator<Item, GetItem>
where
    GetItem: FnMut(u32) -> Item,
{
    size: u32,
    get_item: GetItem,
    index: u32,
}

impl<Item, GetItem> SBIterator<Item, GetItem>
where
    GetItem: FnMut(u32) -> Item,
{
    fn new(size: u32, get_item: GetItem) -> Self {
        Self {
            size: size,
            get_item: get_item,
            index: 0,
        }
    }
}

impl<Item, GetItem> Iterator for SBIterator<Item, GetItem>
where
    GetItem: FnMut(u32) -> Item,
{
    type Item = Item;
    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.size {
            self.index += 1;
            Some((self.get_item)(self.index - 1))
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        return (0, Some(self.size as usize));
    }
}

/////////////////////////////////////////////////////////////////////////////////////////////////////

mod strings;
use strings::*;

mod sbaddress;
mod sbattachinfo;
mod sbbreakpoint;
mod sbbreakpointlocation;
mod sbbroadcaster;
mod sbcommandinterpreter;
mod sbcommandreturnobject;
mod sbdata;
mod sbdebugger;
mod sberror;
mod sbevent;
mod sbexecutioncontext;
mod sbfilespec;
mod sbframe;
mod sbinstruction;
mod sbinstructionlist;
mod sblaunchinfo;
mod sblinenetry;
mod sblistener;
mod sbmodule;
mod sbplatform;
mod sbprocess;
mod sbstream;
mod sbsymbol;
mod sbtarget;
mod sbthread;
mod sbtype;
mod sbvalue;
mod sbvaluelist;

pub use sbaddress::*;
pub use sbattachinfo::*;
pub use sbbreakpoint::*;
pub use sbbreakpointlocation::*;
pub use sbbroadcaster::*;
pub use sbcommandinterpreter::*;
pub use sbcommandreturnobject::*;
pub use sbdata::*;
pub use sbdebugger::*;
pub use sberror::*;
pub use sbevent::*;
pub use sbexecutioncontext::*;
pub use sbfilespec::*;
pub use sbframe::*;
pub use sbinstruction::*;
pub use sbinstructionlist::*;
pub use sblaunchinfo::*;
pub use sblinenetry::*;
pub use sblistener::*;
pub use sbmodule::*;
pub use sbplatform::*;
pub use sbprocess::*;
pub use sbstream::*;
pub use sbsymbol::*;
pub use sbtarget::*;
pub use sbthread::*;
pub use sbtype::*;
pub use sbvalue::*;
pub use sbvaluelist::*;
