#![allow(non_camel_case_types)]

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

mod generated;

pub use generated::*;

impl Default for Breakpoint {
    fn default() -> Self {
        Breakpoint {
            id: None,
            verified: false,
            column: None,
            end_column: None,
            line: None,
            end_line: None,
            message: None,
            source: None,
        }
    }
}

impl Default for StackFrame {
    fn default() -> Self {
        StackFrame {
            id: 0,
            name: String::new(),
            source: None,
            line: 0,
            column: 0,
            end_column: None,
            end_line: None,
            module_id: None,
            presentation_hint: None,
        }
    }
}

impl Default for Scope {
    fn default() -> Self {
        Scope {
            column: None,
            end_column: None,
            end_line: None,
            expensive: false,
            indexed_variables: None,
            line: None,
            name: String::new(),
            named_variables: None,
            source: None,
            variables_reference: 0,
        }
    }
}

impl Default for Variable {
    fn default() -> Self {
        Variable {
            name: String::new(),
            value: String::new(),
            variables_reference: 0,
            type_: None,
            evaluate_name: None,
            indexed_variables: None,
            named_variables: None,
            presentation_hint: None,
        }
    }
}

impl Default for StoppedEventBody {
    fn default() -> Self {
        StoppedEventBody {
            thread_id: None,
            reason: String::new(),
            all_threads_stopped: None,
            description: None,
            preserve_focus_hint: None,
            text: None,
        }
    }
}

impl Default for EvaluateResponseBody {
    fn default() -> Self {
        EvaluateResponseBody {
            result: String::new(),
            type_: None,
            variables_reference: 0,
            indexed_variables: None,
            named_variables: None,
            presentation_hint: None,
        }
    }
}

impl Default for OutputEventBody {
    fn default() -> Self {
        OutputEventBody {
            output: String::new(),
            category: None,
            data: None,
            line: None,
            column: None,
            source: None,
            variables_reference: None,
        }
    }
}
