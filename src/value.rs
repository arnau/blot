// Copyright 2018 Arnau Siches

// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except
// according to those terms.

use std::collections::{HashMap, HashSet};

#[derive(Debug)]
pub enum Value {
    Null,
    Bool(bool),
    Integer(i64),
    String(String),
    Raw(Vec<u8>),
    List(Vec<Value>),
    // HashSet require Hash trait which makes this recursive structure too complex for this
    // exercise
    Set(Vec<Value>),
    Map(HashMap<String, Value>),
}
