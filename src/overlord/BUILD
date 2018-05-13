load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_binary")
load("@io_bazel_rules_docker//go:image.bzl", "go_image")

package(default_visibility = ["//visibility:private"])

go_library(
    name = "go_default_library",
    srcs = ["overlord.go"],
    importpath = "github.com/google/minions/src/overlord",
    deps = [
        "//proto:go_default_library",
        "@org_golang_x_net//context:go_default_library",
    ],
)

go_library(
    name = "overlord",
    srcs = ["overlord.go"],
    importpath = "github.com/google/minions/src/overlord",
    deps = [
        "//proto:go_default_library",
        "@org_golang_x_net//context:go_default_library",
    ],
)

go_binary(
    name = "overlord_runner",
    srcs = ["overlord_runner.go"],
    deps = [
        ":overlord",
        "//proto:go_default_library",
        "@org_golang_google_grpc//:go_default_library",
    ],
)

go_binary(
    name = "overlord_test_client",
    srcs = ["overlord_test_client.go"],
    deps = [
        "//proto:go_default_library",
        "@org_golang_google_grpc//:go_default_library",
        "@org_golang_x_net//context:go_default_library",
    ],
)

go_image(
    name = "overlord_docker",
    binary = ":overlord_runner",
)
