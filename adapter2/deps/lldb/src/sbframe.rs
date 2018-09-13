use super::*;

cpp_class!(pub unsafe struct SBFrame as "SBFrame");

unsafe impl Send for SBFrame {}

impl SBFrame {
    pub fn is_valid(&self) -> bool {
        cpp!(unsafe [self as "SBFrame*"] -> bool as "bool" {
            return self->IsValid();
        })
    }
    pub fn function_name(&self) -> Option<&str> {
        let ptr = cpp!(unsafe [self as "SBFrame*"] -> *const c_char as "const char*" {
            return self->GetFunctionName();
        });
        if ptr.is_null() {
            None
        } else {
            unsafe { Some(CStr::from_ptr(ptr).to_str().unwrap()) }
        }
    }
    pub fn display_function_name(&self) -> Option<&str> {
        let ptr = cpp!(unsafe [self as "SBFrame*"] -> *const c_char as "const char*" {
            return self->GetDisplayFunctionName();
        });
        if ptr.is_null() {
            None
        } else {
            unsafe { Some(CStr::from_ptr(ptr).to_str().unwrap()) }
        }
    }
    pub fn line_entry(&self) -> Option<SBLineEntry> {
        let line_entry = cpp!(unsafe [self as "SBFrame*"] -> SBLineEntry as "SBLineEntry" {
            return self->GetLineEntry();
        });
        if line_entry.is_valid() {
            Some(line_entry)
        } else {
            None
        }
    }
    pub fn pc_address(&self) -> SBAddress {
        cpp!(unsafe [self as "SBFrame*"] -> SBAddress as "SBAddress" {
            return self->GetPCAddress();
        })
    }
    pub fn thread(&self) -> SBThread {
        cpp!(unsafe [self as "SBFrame*"] -> SBThread as "SBThread" {
            return self->GetThread();
        })
    }
    pub fn variables(&self, options: &VariableOptions) -> SBValueList {
        let VariableOptions {
            arguments,
            locals,
            statics,
            in_scope_only,
            use_dynamic,
        } = *options;
        cpp!(unsafe [self as "SBFrame*", arguments as "bool", locals as "bool", statics as "bool",
                     in_scope_only as "bool", use_dynamic as "uint32_t"] -> SBValueList as "SBValueList" {
            return self->GetVariables(arguments, locals, statics, in_scope_only, (lldb::DynamicValueType)use_dynamic);
        })
    }
    pub fn find_variable(&self, name: &str) -> Option<SBValue> {
        let var = with_cstr(name, |name| {
            cpp!(unsafe [self as "SBFrame*", name as "const char*"] -> SBValue as "SBValue" {
                return self->FindVariable(name);
            })
        });
        if var.is_valid() {
            Some(var)
        } else {
            None
        }
    }
    pub fn evaluate_expression(&self, expr: &str) -> SBValue {
        with_cstr(expr, |expr| {
            cpp!(unsafe [self as "SBFrame*", expr as "const char*"] -> SBValue as "SBValue" {
                return self->EvaluateExpression(expr);
            })
        })
    }
    pub fn registers(&self) -> SBValueList {
        cpp!(unsafe [self as "SBFrame*"] -> SBValueList as "SBValueList" {
            return self->GetRegisters();
        })
    }
    pub fn pc(&self) -> Address {
        cpp!(unsafe [self as "SBFrame*"] -> Address as "addr_t" {
            return self->GetPC();
        })
    }
    pub fn sp(&self) -> Address {
        cpp!(unsafe [self as "SBFrame*"] -> Address as "addr_t" {
            return self->GetSP();
        })
    }
    pub fn fp(&self) -> Address {
        cpp!(unsafe [self as "SBFrame*"] -> Address as "addr_t" {
            return self->GetFP();
        })
    }
}

impl fmt::Debug for SBFrame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        debug_descr(f, |descr| {
            cpp!(unsafe [self as "SBFrame*", descr as "SBStream*"] -> bool as "bool" {
                return self->GetDescription(*descr);
            })
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct VariableOptions {
    pub arguments: bool,
    pub locals: bool,
    pub statics: bool,
    pub in_scope_only: bool,
    pub use_dynamic: DynamicValueType,
}

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
#[repr(u32)]
pub enum DynamicValueType {
    NoDynamicValues = 0,
    DynamicCanRunTarget = 1,
    DynamicDontRunTarget = 2,
}
