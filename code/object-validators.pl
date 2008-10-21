# -*- Mode: perl; indent-tabs-mode: nil -*-
#
# The contents of this file are subject to the Mozilla Public
# License Version 1.1 (the "License"); you may not use this file
# except in compliance with the License. You may obtain a copy of
# the License at http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS
# IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
# implied. See the License for the specific language governing
# rights and limitations under the License.
#
# The Original Code is the Bugzilla SecureMail Extension
#
# The Initial Developer of the Original Code is the Mozilla Corporation.
# Portions created by the Initial Developer are Copyright (C) 2008 the 
# Initial Developer. All Rights Reserved.
#
# Contributor(s): Max Kanat-Alexander <mkanat@bugzilla.org>

use strict;
use Bugzilla;
use Bugzilla::Object;
use Crypt::OpenPGP::KeyRing;

my %args = %{ Bugzilla->hook_args };
my ($invocant, $validators) = @args{qw(invocant validators)};

if ($invocant->isa('Bugzilla::Group')) {
    $validators->{'secure_mail'} = \&Bugzilla::Object::check_boolean;
}
elsif ($invocant->isa('Bugzilla::User')) {
    $validators->{'public_key'} = sub {
        my ($self, $value) = @_;
        # FIXME Should actually validate that we can read the key.
        $value = trim($value) || '';
        if ($value ne '') {
            my $ring = new Crypt::OpenPGP::KeyRing(Data => $value);
            $ring->read if $ring;
            if (!defined $ring || !scalar $ring->blocks) {
                ThrowUserError('securemail_invalid_key');
            }
        }
        return $value;
    };
}
