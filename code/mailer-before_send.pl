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
use Bugzilla::User;
use Bugzilla::Util qw(correct_urlbase);
use Crypt::OpenPGP;
use Crypt::OpenPGP::KeyRing;

my $email = Bugzilla->hook_args->{email};
if (my $user_id = $email->header('X-Bugzila-SecureMail-Encrypt')) {

    my $bug_id;
    my $old_subject = $email->header('Subject');
    if ($bug_id = $email->header('X-Bugzilla-Bug-Id')) {
        my $new_subject = $old_subject;
        # XXX This won't work if somebody's changed the Subject format.
        $new_subject =~ s/($bug_id\])\s+(.*)$/$1 (Secure bug updated)/;
        $email->header_set('Subject', $new_subject);
    }

    my $user = new Bugzilla::User($user_id);
    my $key = $user->{public_key};
    if ($key) {
        my $body = $email->body;
        if ($bug_id) {
            $body = "Subject: $old_subject\n\n" . $body;
        }
        my $pubring = new Crypt::OpenPGP::KeyRing(Data => $key);
        my $pgp = new Crypt::OpenPGP(PubRing => $pubring);
        # "@" matches every key in the public key ring, which is fine, because
        # there's only one key in our keyring.
        my $encrypted = $pgp->encrypt(
            Data => $body, Recipients => "@", Armour => 1);
        if (defined $encrypted) {
            $email->body_set($encrypted);
        }
        else {
            $email->body_set('Error during Encryption: ' . $pgp->errstr);
        }
    }
    else {
        my $urlbase = correct_urlbase();
        my $text = <<EOT;
This email would have contained sensitive information, and you have 
not set a PGP/GPG key in the "Name and Password" section of your user
preferences. In order to receive similar mails in the future, please go
to ${urlbase}userprefs.cgi?tab=account
and set a PGP/GPG key.
EOT
        if ($bug_id) {
            $text .= <<EOT;

You can see this bug's current state at: 
${urlbase}show_bug.cgi?id=$bug_id
EOT
        }
        else {
            my $maintainer = Bugzilla->params->{'maintainer'};
            $text .= "\nYou will have to contact $maintainer to reset"
                     . " your password.";
        }
        $email->body_set($text);
    }
}
