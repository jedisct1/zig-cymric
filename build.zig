const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const cymric_module = b.createModule(.{
        .root_source_file = b.path("src/cymric.zig"),
        .target = target,
        .optimize = optimize,
    });

    const cymric_lib = b.addLibrary(.{
        .name = "cymric",
        .root_module = cymric_module,
    });

    b.installArtifact(cymric_lib);

    const main_exe = b.addExecutable(.{
        .name = "cymric-example",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "cymric", .module = cymric_module },
            },
        }),
    });

    b.installArtifact(main_exe);

    const run_cmd = b.addRunArtifact(main_exe);
    run_cmd.step.dependOn(b.getInstallStep());

    const run_step = b.step("run", "Run the example");
    run_step.dependOn(&run_cmd.step);

    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/cymric.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
