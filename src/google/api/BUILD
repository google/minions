# gazelle:ignore
load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")

proto_library(
    name = "annotations_proto",
    srcs = [
        "annotations.proto",
        "http.proto",
    ],
    visibility = ["//visibility:public"],
    deps = ["@com_google_protobuf//:descriptor_proto"],
)

go_proto_library(
    name = "annotations_go_proto",
    importpath = "google.golang.org/genproto/googleapis/api/annotations",
    proto = ":annotations_proto",
    visibility = ["//visibility:public"],
    deps = ["@com_github_golang_protobuf//protoc-gen-go/descriptor:go_default_library"],
)

alias(
    name = "go_default_library",
    actual = "@org_golang_google_genproto//googleapis/api/annotations:go_default_library",
    visibility = ["//visibility:public"],
)
