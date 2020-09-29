use crate::generator::Generator;
use molecule_codegen::{ast};
use std::io;
use std::fmt::{Write, Result};

pub const VERSION : u32 = 6001;

pub fn generate(output: &mut Output, ast: &ast::Ast) -> Result {
    for decl in ast.major_decls() {
        match decl.as_ref() {
            ast::TopDecl::Option_(ref i) => i.generate(output)?,
            ast::TopDecl::Union(ref i) => i.generate(output)?,
            ast::TopDecl::Array(ref i) => i.generate(output)?,
            ast::TopDecl::Struct(ref i) => i.generate(output)?,
            ast::TopDecl::FixVec(ref i) => i.generate(output)?,
            ast::TopDecl::DynVec(ref i) => i.generate(output)?,
            ast::TopDecl::Table(ref i) => i.generate(output)?,
            ast::TopDecl::Primitive(_) => unreachable!(),
        };
    }
    Ok(())
}

pub struct Output {
    decl: String,
    def: String,
    imp: String
}

impl Output {
    pub fn new() -> Output {
        Output {
            decl: String::new(),
            def: String::new(),
            imp: String::new()
        }
    }

    pub fn write_decl(&mut self, s: &str) {
        self.decl += s;
        self.decl += "\n";
    }
    pub fn write_def(&mut self, s: &str) {
        self.def += s;
        self.def += "\n";
    }
    pub fn write_imp(&mut self, s: &str) {
        self.imp += s;
        self.def += "\n";
    }

    pub fn combine(&self, name: &str) -> String {
        let mut res = String::new();
        let name = name.to_uppercase();
        res.push_str(&format!(r###"
        #ifndef _{0}_API2_H_
        #define _{0}_API2_H_
        "###, name));
        let prefix = format!(r###"
// Generated by Molecule 0.6.1
#define MOLECULEC_VERSION {0}
#define MOLECULE_API_VERSION_MIN 5000

#define MOLECULEC2_VERSION {0}
#define MOLECULE2_API_VERSION_MIN 5000

#include "molecule2_reader.h"

#ifdef __cplusplus
extern "C" {{
#endif /* __cplusplus */
        "###, VERSION);

        res.push_str(&prefix);

        res.push_str("\n// ----forward declaration--------\n");
        res.push_str(&self.decl);
        res.push_str("\n// ----definition-----------------\n");
        res.push_str(&self.def);

        res.push_str("\n#ifndef MOLECULEC_C2_DECLARATION_ONLY\n");
        res.push_str("\n// ----implementation-------------\n");
        res.push_str(&self.imp);
        res.push_str("\n#endif // MOLECULEC_C2_DECLARATION_ONLY\n");

        let suffix = format!(r###"
#ifdef __cplusplus
}}
#endif /* __cplusplus */
        "###);
        res.push_str(&suffix);
        res.push_str(&format!(r###"
        #endif // _{0}_API2_H_
        "###, name));
        return res;
    }
}

// now we can use write!(&output, "{}", ...) now
impl Write for Output {
    fn write_str(&mut self, s: &str) -> Result {
        self.write_def(s);
        Ok(())
    }
}
