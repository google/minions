load("@io_bazel_rules_go//go:def.bzl", "go_library")

package(
    default_visibility = ["//visibility:public"],
)

load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")

proto_library(
    name = "overlord_proto",
    srcs = ["overlord.proto"],
    deps = ["//google/api:annotations_proto"],
)

go_proto_library(
    name = "overlord_go_proto",
    compilers = ["@io_bazel_rules_go//proto:go_grpc"],
    importpath = "github.com/paradoxengine/minions/proto/overlord",
    proto = ":overlord_proto",
    deps = ["//google/api:annotations_go_proto"],
)

go_library(
    name = "go_default_library",
    embed = [":overlord_go_proto"],
    importpath = "github.com/paradoxengine/minions/proto/overlord",
)
