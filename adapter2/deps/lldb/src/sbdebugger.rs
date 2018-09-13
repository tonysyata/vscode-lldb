use super::*;

cpp_class!(pub unsafe struct SBDebugger as "SBDebugger");

unsafe impl Send for SBDebugger {}

impl SBDebugger {
    pub fn initialize() {
        cpp!(unsafe [] {
            SBDebugger::Initialize();
        })
    }
    pub fn terminate() {
        cpp!(unsafe [] {
            SBDebugger::Terminate();
        })
    }
    pub fn create(source_init_files: bool) -> SBDebugger {
        cpp!(unsafe [source_init_files as "bool"] -> SBDebugger as "SBDebugger" {
            return SBDebugger::Create(source_init_files);
        })
    }
    pub fn is_valid(&self) -> bool {
        cpp!(unsafe [self as "SBDebugger*"] -> bool as "bool" {
            return self->IsValid();
        })
    }
    pub fn clear(&self) {
        cpp!(unsafe [self as "SBDebugger*"] {
            return self->Clear();
        })
    }
    pub fn async(&self) -> bool {
        cpp!(unsafe [self as "SBDebugger*"]-> bool as "bool" {
            return self->GetAsync();
        })
    }
    pub fn set_async(&self, async: bool) {
        cpp!(unsafe [self as "SBDebugger*", async as "bool"] {
            self->SetAsync(async);
        })
    }
    pub fn create_target(
        &self, executable: &str, target_triple: Option<&str>, platform_name: Option<&str>, add_dependent_modules: bool,
    ) -> Result<SBTarget, SBError> {
        with_cstr(executable, |executable| {
            with_opt_cstr(target_triple, |target_triple| {
                with_opt_cstr(platform_name, |platform_name| {
                    let mut error = SBError::new();
                    let target = cpp!(unsafe [self as "SBDebugger*", executable as "const char*", target_triple as "const char*",
                                              platform_name as "const char*", add_dependent_modules as "bool", mut error as "SBError"
                                             ] -> SBTarget as "SBTarget" {
                            return self->CreateTarget(executable, target_triple, platform_name, add_dependent_modules, error);
                        });
                    if error.is_success() {
                        Ok(target)
                    } else {
                        Err(error)
                    }
                })
            })
        })
    }
    pub fn selected_target(&self) -> SBTarget {
        cpp!(unsafe [self as "SBDebugger*"] -> SBTarget as "SBTarget" {
            return self->GetSelectedTarget();
        })
    }
    pub fn set_selected_target(&self, target: &SBTarget) {
        cpp!(unsafe [self as "SBDebugger*", target as "SBTarget*"] {
            self->SetSelectedTarget(*target);
        })
    }
    pub fn selected_platform(&self) -> SBPlatform {
        cpp!(unsafe [self as "SBDebugger*"] -> SBPlatform as "SBPlatform" {
            return self->GetSelectedPlatform();
        })
    }
    pub fn set_selected_platform(&self, platform: &SBPlatform) {
        cpp!(unsafe [self as "SBDebugger*", platform as "SBPlatform*"] {
            self->SetSelectedPlatform(*platform);
        })
    }
    pub fn command_interpreter(&self) -> SBCommandInterpreter {
        cpp!(unsafe [self as "SBDebugger*"] ->  SBCommandInterpreter as "SBCommandInterpreter" {
            return self->GetCommandInterpreter();
        })
    }
}

impl fmt::Debug for SBDebugger {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        debug_descr(f, |descr| {
            cpp!(unsafe [self as "SBDebugger*", descr as "SBStream*"] -> bool as "bool" {
                return self->GetDescription(*descr);
            })
        })
    }
}
