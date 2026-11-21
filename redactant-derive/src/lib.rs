// SPDX-License-Identifier: MIT OR Apache-2.0

//! `#[derive(Redact)]` for redactant (DERIVE.md slices 2-3: structs and enums). Re-exported as `redactant::Redact` under feature
//! `derive`; depend on `redactant`, not on this crate.
//!
//! Every field must state what it may reveal: `#[redact(keep)]`, `#[redact(fingerprint)]`, `#[redact]` (withhold) or
//! `#[redact(nested)]`. A `Secret<..>` field needs no attribute. An unannotated field is a compile error unless the
//! struct says `#[redact(default = "redact")]` (or `"fingerprint"`; `"keep"` is refused).

use proc_macro::TokenStream;
use proc_macro2::{TokenStream as Tokens, TokenTree};
use quote::{format_ident, quote, quote_spanned};
use syn::spanned::Spanned;
use syn::{Data, DeriveInput, Fields, Index, LitStr, Type, parse_macro_input};

#[proc_macro_derive(Redact, attributes(redact))]
pub fn derive_redact(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

#[derive(Clone, Copy, PartialEq)]
enum Disp {
    Keep,
    Fingerprint,
    Redact,
    Nested,
    /// A `Secret<..>` field with no attribute: described through its own `Redact` impl, which withholds it.
    Secret,
}

impl Disp {
    fn label(self) -> &'static str {
        match self {
            Disp::Keep => "keep",
            Disp::Fingerprint => "fingerprint",
            Disp::Redact => "redact",
            Disp::Nested => "nested",
            Disp::Secret => "secret",
        }
    }
}

const CHOICES: &str =
    "#[redact(keep)], #[redact(fingerprint)], #[redact] (withhold) or #[redact(nested)]";

/// True when the type is written `Secret<..>` (possibly path-qualified). A type alias of it is not recognised, so the
/// author annotates that field; the failure direction is a compile error, never a leak.
fn is_secret(ty: &Type) -> bool {
    match ty {
        Type::Path(p) => p.path.segments.last().is_some_and(|s| s.ident == "Secret"),
        Type::Paren(p) => is_secret(&p.elem),
        Type::Group(g) => is_secret(&g.elem),
        _ => false,
    }
}

fn field_disposition(field: &syn::Field) -> syn::Result<Option<Disp>> {
    let mut found: Option<Disp> = None;
    for attr in &field.attrs {
        if !attr.path().is_ident("redact") {
            continue;
        }
        let mut this: Option<Disp> = None;
        match &attr.meta {
            syn::Meta::Path(_) => this = Some(Disp::Redact),
            syn::Meta::List(_) => {
                attr.parse_nested_meta(|m| {
                    let d = if m.path.is_ident("keep") {
                        Disp::Keep
                    } else if m.path.is_ident("fingerprint") {
                        Disp::Fingerprint
                    } else if m.path.is_ident("nested") {
                        Disp::Nested
                    } else if m.path.is_ident("redact") {
                        Disp::Redact
                    } else if m.path.is_ident("skip") {
                        return Err(m.error(
                            "`skip` is not offered: a field the sink never sees is a field no reviewer can see was \
                             dropped on purpose; use #[redact] to withhold it",
                        ));
                    } else {
                        return Err(m.error(format!("unknown redact option; expected one of {CHOICES}")));
                    };
                    if this.replace(d).is_some() {
                        return Err(m.error("conflicting redact options on one field: state exactly one"));
                    }
                    Ok(())
                })?;
                if this.is_none() {
                    return Err(syn::Error::new_spanned(
                        attr,
                        format!("empty #[redact()]; expected one of {CHOICES}"),
                    ));
                }
            }
            syn::Meta::NameValue(_) => {
                return Err(syn::Error::new_spanned(
                    attr,
                    format!("expected one of {CHOICES}"),
                ));
            }
        }
        if found.is_some() {
            return Err(syn::Error::new_spanned(
                attr,
                "a field takes one #[redact] attribute",
            ));
        }
        found = this;
    }
    Ok(found)
}

fn default_of(attrs: &[syn::Attribute], what: &str) -> syn::Result<Option<Disp>> {
    let mut default = None;
    for attr in attrs {
        if !attr.path().is_ident("redact") {
            continue;
        }
        attr.parse_nested_meta(|m| {
            if !m.path.is_ident("default") {
                return Err(m.error(format!(
                    "on {what} only `default = \"redact\"` or `default = \"fingerprint\"` is accepted"
                )));
            }
            let lit: LitStr = m.value()?.parse()?;
            default = Some(match lit.value().as_str() {
                "redact" => Disp::Redact,
                "fingerprint" => Disp::Fingerprint,
                "keep" => {
                    return Err(syn::Error::new_spanned(
                        &lit,
                        "`default = \"keep\"` is not accepted: the safe direction must be the cheap one; annotate each \
                         kept field with #[redact(keep)]",
                    ));
                }
                _ => return Err(syn::Error::new_spanned(&lit, "expected \"redact\" or \"fingerprint\"")),
            });
            Ok(())
        })?;
    }
    Ok(default)
}

/// Does the token stream mention any of these identifiers? Used to add a where-bound only for field types that depend
/// on a generic parameter (a bound on a concrete type is checked by the generated body instead).
fn mentions(ty: &Type, params: &[syn::Ident]) -> bool {
    fn walk(ts: Tokens, params: &[syn::Ident]) -> bool {
        ts.into_iter().any(|t| match t {
            TokenTree::Ident(i) => params.contains(&i),
            TokenTree::Group(g) => walk(g.stream(), params),
            _ => false,
        })
    }
    walk(quote!(#ty), params)
}

/// What the fields of one struct or variant contribute to the generated impl.
struct Parts {
    steps: Vec<Tokens>,
    schema: Vec<Tokens>,
    bounds: Vec<Tokens>,
}

/// `access(i, member, span)` is an expression of type `&FieldType` for field `i`, spanned at the field so a type error
/// points at it.
fn field_parts(
    fields: &Fields,
    owner: &str,
    default: Option<Disp>,
    params: &[syn::Ident],
    access: &dyn Fn(usize, &Tokens, proc_macro2::Span) -> Tokens,
) -> syn::Result<Parts> {
    let list: Vec<&syn::Field> = match fields {
        Fields::Named(f) => f.named.iter().collect(),
        Fields::Unnamed(f) => f.unnamed.iter().collect(),
        Fields::Unit => Vec::new(),
    };
    let mut parts = Parts {
        steps: Vec::new(),
        schema: Vec::new(),
        bounds: Vec::new(),
    };
    for (i, field) in list.iter().enumerate() {
        let (member, label) = match &field.ident {
            Some(id) => (quote!(#id), id.to_string()),
            None => {
                let idx = Index::from(i);
                (quote!(#idx), i.to_string())
            }
        };
        let secret = is_secret(&field.ty);
        let disp = match (field_disposition(field)?, secret) {
            (Some(Disp::Keep), true) => {
                return Err(syn::Error::new_spanned(
                    field,
                    "a `Secret<..>` field cannot be `keep`: its type already says withhold; remove the attribute",
                ));
            }
            (Some(d), _) => d,
            (None, true) => Disp::Secret,
            (None, false) => match default {
                Some(d) => d,
                None => {
                    return Err(syn::Error::new_spanned(
                        field,
                        format!(
                            "field `{label}` of `{owner}` must state what it may reveal: add {CHOICES}"
                        ),
                    ));
                }
            },
        };
        let ty = &field.ty;
        let span = field.span();
        let r = access(i, &member, span);
        let action = match disp {
            Disp::Keep => quote_spanned! {span=>
                __sink.field(&__p, ::redactant::Disposition::Kept(#r));
            },
            // `let _ = <ref>` counts as a use, so a withheld field does not draw a dead_code warning at the caller.
            Disp::Redact => quote_spanned! {span=>
                let _ = #r;
                __sink.field(&__p, ::redactant::Disposition::Redacted);
            },
            Disp::Fingerprint => quote_spanned! {span=>
                __sink.field(&__p, __cx.fingerprint(::core::convert::AsRef::<[u8]>::as_ref(#r)));
            },
            Disp::Nested | Disp::Secret => quote_spanned! {span=>
                ::redactant::Redact::describe_at(#r, &__p, __cx, __sink);
            },
        };
        parts.steps.push(quote! {
            __p.push(::redactant::Segment::Field(#label));
            #action
            __p.pop();
        });
        let lbl = disp.label();
        parts.schema.push(if disp == Disp::Nested {
            quote! {
                __s.push_str(#label); __s.push_str(":nested(");
                __s.push_str(&<#ty as ::redactant::Redact>::schema());
                __s.push_str("),");
            }
        } else {
            let entry = format!("{label}:{lbl},");
            quote!(__s.push_str(#entry);)
        });
        if mentions(ty, params) {
            match disp {
                Disp::Nested => parts.bounds.push(quote!(#ty: ::redactant::Redact)),
                Disp::Keep => parts.bounds.push(quote!(#ty: ::redactant::Keep)),
                Disp::Fingerprint => parts.bounds.push(quote!(#ty: ::core::convert::AsRef<[u8]>)),
                Disp::Redact | Disp::Secret => {}
            }
        }
    }
    Ok(parts)
}

fn expand(input: &DeriveInput) -> syn::Result<Tokens> {
    let name = &input.ident;
    let type_default = default_of(&input.attrs, "a struct or enum")?;
    let params: Vec<syn::Ident> = input
        .generics
        .type_params()
        .map(|p| p.ident.clone())
        .collect();
    let mut bounds: Vec<Tokens> = Vec::new();
    let open = format!("{name}{{");
    let (body, schema_body) = match &input.data {
        Data::Struct(s) => {
            let access =
                |_: usize, m: &Tokens, sp: proc_macro2::Span| quote_spanned!(sp=> &self.#m);
            let p = field_parts(&s.fields, &name.to_string(), type_default, &params, &access)?;
            bounds.extend(p.bounds);
            let steps = p.steps;
            let schema = p.schema;
            (quote! { #(#steps)* }, quote! { #(#schema)* })
        }
        Data::Enum(e) => {
            let mut arms = Vec::new();
            let mut schema_arms = Vec::new();
            for v in &e.variants {
                let vname = &v.ident;
                let vlabel = vname.to_string();
                let default = default_of(&v.attrs, "a variant")?.or(type_default);
                let binding = |i: usize, _: &Tokens, sp: proc_macro2::Span| {
                    let b = proc_macro2::Ident::new(&format!("__f{i}"), sp);
                    quote!(#b)
                };
                let p = field_parts(
                    &v.fields,
                    &format!("{name}::{vlabel}"),
                    default,
                    &params,
                    &binding,
                )?;
                bounds.extend(p.bounds);
                let steps = p.steps;
                let schema = p.schema;
                let n = match &v.fields {
                    Fields::Named(f) => f.named.len(),
                    Fields::Unnamed(f) => f.unnamed.len(),
                    Fields::Unit => 0,
                };
                let pat = match &v.fields {
                    Fields::Named(f) => {
                        let ids = f.named.iter().map(|x| x.ident.clone().unwrap());
                        let bs = (0..n).map(|i| format_ident!("__f{}", i));
                        quote!(Self::#vname { #(#ids: #bs),* })
                    }
                    Fields::Unnamed(_) => {
                        let bs = (0..n).map(|i| format_ident!("__f{}", i));
                        quote!(Self::#vname ( #(#bs),* ))
                    }
                    Fields::Unit => quote!(Self::#vname),
                };
                // A variant with no fields still reports itself: one kept `()` at its Variant path.
                let unit = if n == 0 {
                    quote!(__sink.field(&__p, ::redactant::Disposition::Kept(&()));)
                } else {
                    quote!()
                };
                arms.push(quote! {
                    #pat => {
                        __p.push(::redactant::Segment::Variant(#vlabel));
                        #unit
                        #(#steps)*
                        __p.pop();
                    }
                });
                let vopen = format!("{vlabel}{{");
                schema_arms.push(quote! {
                    __s.push_str(#vopen);
                    #(#schema)*
                    __s.push_str("},");
                });
            }
            let empty = if e.variants.is_empty() {
                quote!(_ => {})
            } else {
                quote!()
            };
            let match_arms = arms;
            (
                quote! { match self { #(#match_arms)* #empty } },
                quote! { #(#schema_arms)* },
            )
        }
        Data::Union(_) => {
            return Err(syn::Error::new_spanned(
                name,
                "#[derive(Redact)] does not support unions",
            ));
        }
    };

    let (impl_g, ty_g, where_clause) = input.generics.split_for_impl();
    let mut preds = where_clause
        .map(|w| w.predicates.clone())
        .unwrap_or_default();
    for b in bounds {
        preds.push(syn::parse2(b)?);
    }
    let where_tokens = if preds.is_empty() {
        quote!()
    } else {
        quote!(where #preds)
    };
    Ok(quote! {
        impl #impl_g ::redactant::Redact for #name #ty_g #where_tokens {
            fn describe_at(
                &self,
                __path: &[::redactant::Segment<'_>],
                __cx: &::redactant::Context<'_>,
                __sink: &mut dyn ::redactant::Sink,
            ) {
                let _ = (&__cx, &__sink);
                let mut __p: ::std::vec::Vec<::redactant::Segment<'_>> = __path.to_vec();
                #body
                let _ = &mut __p;
            }

            fn schema() -> ::std::string::String {
                let mut __s = ::std::string::String::from(#open);
                #schema_body
                __s.push('}');
                __s
            }
        }
    })
}
