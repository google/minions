package(default_visibility = ["//visibility:public"])
load("@bazel_gazelle//:def.bzl", "gazelle")
load("@io_bazel_rules_go//go:def.bzl", "go_prefix")

go_prefix("github.com/paradoxengine/minions")
gazelle(
    name = "gazelle",
    prefix = "github.com/paradoxengine/minions/src",
    command = "fix"
)
