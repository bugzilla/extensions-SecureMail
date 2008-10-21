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
my %args = %{ Bugzilla->hook_args };
my ($message, $bug_id, $to) = @args{qw(message bug_id to)};
my $bug = Bugzilla::Bug->new($bug_id);
my $groups = $bug->groups_in;
if (grep($_->{secure_mail}, @$groups)) {
    # Adding a header is the only way to pass a "message" to MessageToMTA, 
    # since we only have text here, and no object.
    my $user_id = $to->id;
    $$message = "X-Bugzila-SecureMail-Encrypt: $user_id\n"
                . "X-Bugzilla-Bug-Id: $bug_id\n" . $$message;
}
