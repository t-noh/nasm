#!/usr/bin/perl
use strict;
use warnings;

my ($static_file, $insns_file, $output_file) = @ARGV;

unless ($static_file && $insns_file && $output_file) {
    die "Usage: $0 <lfi-static.mac.in> <lfi_insns.dat> <output_file>\n";
}

# 1. Read lfi_insns.dat
my %insns_with_mem = ();
open(my $ins_fh, '<', $insns_file) or die "Cannot open $insns_file: $!\n";
while (<$ins_fh>) {
    chomp;
    next if /^\s*#/ || /^\s*$/;
    my ($name, $counts_str, @op_positions) = split(/\s+/);
    my @counts = split(/,/, $counts_str);
    $insns_with_mem{$name} = {
        counts => \@counts,
        positions => \@op_positions
    };
}
close($ins_fh);

# 2. Copy static part
open(my $in, '<', $static_file) or die "Cannot open $static_file: $!\n";
open(my $out, '>', $output_file) or die "Cannot open $output_file: $!\n";

while (<$in>) {
    print $out $_;
}
close($in);

print $out "\n;; --- Automatically Generated Overrides ---\n\n";

# 3. Define exceptions and static handled
my %read_only_binary = map { $_ => 1 } qw(cmp test bt bound);
my %read_only_unary  = map { $_ => 1 } qw(push);
my %static_handled   = map { $_ => 1 } qw(pop lea jmp call ret syscall nop);

# 4. Generate overrides for ALL memory-accessing instructions
foreach my $op (sort keys %insns_with_mem) {
    next if $static_handled{$op};

    my $info = $insns_with_mem{$op};
    my @counts = @{$info->{counts}};

    # We might have multiple counts (e.g. 1 and 2). We generate macros for each supported count.
    my %generated = (); # prevent duplicate macros for same count (should not happen but safe)

    foreach my $count (@counts) {
        next if $generated{$count};

        if ($count == 3) {
            # We assume 3-operand instructions are write-dest (true for AVX/BMI1)
            print $out "%imacro $op 3\n";
            print $out "    LFI_TERNARY_OP $op, %1, %2, %3\n";
            print $out "%endmacro\n\n";
            $generated{$count} = 1;
        } elsif ($count == 2) {
            if ($read_only_binary{$op}) {
                print $out "%imacro $op 2\n";
                print $out "    LFI_BINARY_OP_RO $op, %1, %2\n";
                print $out "%endmacro\n\n";
            } else {
                print $out "%imacro $op 2\n";
                print $out "    LFI_BINARY_OP $op, %1, %2\n";
                print $out "%endmacro\n\n";
            }
            $generated{$count} = 1;
        } elsif ($count == 1) {
            if ($read_only_unary{$op}) {
                print $out "%imacro $op 1\n";
                print $out "    LFI_UNARY_OP_RO $op, %1\n";
                print $out "%endmacro\n\n";
            } else {
                print $out "%imacro $op 1\n";
                print $out "    LFI_UNARY_OP $op, %1\n";
                print $out "%endmacro\n\n";
            }
            $generated{$count} = 1;
        }
        # We silently skip count 0, 4+ for now.
    }
}

close($out);
