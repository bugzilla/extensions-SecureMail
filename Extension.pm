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
# The Initial Developer of the Original Code is Mozilla.
# Portions created by Mozilla are Copyright (C) 2008 Mozilla Corporation.
# All Rights Reserved.
#
# Contributor(s): Max Kanat-Alexander <mkanat@bugzilla.org>
#                 Gervase Markham <gerv@gerv.net>

package Bugzilla::Extension::Securemail;
use strict;
use base qw(Bugzilla::Extension);

use Bugzilla::Group;
use Bugzilla::Object;
use Bugzilla::User;
use Bugzilla::Util qw(correct_urlbase trim trick_taint);
use Bugzilla::Error;
use Crypt::OpenPGP::KeyRing;
use Crypt::OpenPGP;
use Crypt::SMIME;

our $VERSION = '0.2';

# Add the necessary columns which the extension uses to the database.
#
# secure_mail boolean in the 'groups' table - whether to send secure mail
# public_key text in the 'profiles' table - stores public key
sub install_update_db {
    my ($self, $args) = @_;
    
    my $dbh = Bugzilla->dbh;
    $dbh->bz_add_column('groups', 'secure_mail', 
        {TYPE => 'BOOLEAN', NOTNULL => 1, DEFAULT => 0});
    $dbh->bz_add_column('profiles', 'public_key', { TYPE => 'LONGTEXT' });
}

# Make sure generic functions know about the additional fields in the user
# and group objects
sub object_columns {
    my ($self, $args) = @_;
    
    my %args = %{ $args };
    my ($invocant, $columns) = @args{qw(class columns)};
    if ($invocant->isa('Bugzilla::Group')) {
        push(@$columns, 'secure_mail');
    }
    elsif ($invocant->isa('Bugzilla::User')) {
        push(@$columns, 'public_key');
    }
}

# Plug appropriate validators so we can check the validity of the two 
# fields created by this extension, when new values are submitted.
sub object_validators {
    my ($self, $args) = @_;
    my %args = %{ $args };
    my ($invocant, $validators) = @args{qw(class validators)};
    
    if ($invocant->isa('Bugzilla::Group')) {
        $validators->{'secure_mail'} = \&Bugzilla::Object::check_boolean;
    }
    elsif ($invocant->isa('Bugzilla::User')) {
        $validators->{'public_key'} = sub {
            my ($self, $value) = @_;
            $value = trim($value) || '';
            if ($value =~ /PUBLIC KEY/) {
                my $ring = new Crypt::OpenPGP::KeyRing(Data => $value);
                $ring->read if $ring;
                if (!defined $ring || !scalar $ring->blocks) {
                    ThrowUserError('securemail_invalid_key');
                }
            }
            elsif ($value =~ /BEGIN CERTIFICATE/) {
                # Crypt::SMIME seems not to like tainted values - it claims
                # they aren't scalars!
                trick_taint($value);

                my $smime = Crypt::SMIME->new();
                
                eval {
                    $smime->setPublicKey([$value]);
                };                
                if ($@) {
                    ThrowUserError('securemail_invalid_key');
                }
            }
            else {
                ThrowUserError('securemail_invalid_key');
            }
            
            return $value;
        };
    }
}

# When creating a 'group' object, set up the secure_mail field appropriately.
sub object_before_create {
    my ($self, $args) = @_;
    my %args = %{ $args };
    my ($class, $params, $input) = @args{qw(class params input_params)};
    
    if ($class->isa('Bugzilla::Group')) {
        $params->{secure_mail} = $input->{secure_mail};
    }
}

# On update, set the value of the secure_mail field from the form submission.
sub group_end_of_set_all {
    my ($self, $args) = @_;
    my %args = %{ $args };
    my ($group, $params) = @args{qw(group params)};
    
    $group->set('secure_mail', $params->{secure_mail});
}

# On update, set the value of the public_key field from the form submission. 
sub user_email_save {
    my ($self, $args) = @_;
    my %args = %{ $args };
    my ($user, $params) = @args{qw(user params)};
    
    $user->set('public_key', $params->{public_key});
    $user->update();
}

# Detect the creation of mails which need to be encrypted, and mark them
# as such by adding a header for detection later. (Header is added by template
# hooks.)
sub template_before_process {
    my ($self, $args) = @_;
    my %args = %{ $args };
    my ($vars, $file, $context) = @args{qw(vars file context)};
  
    if ($file eq 'email/newchangedmail.txt.tmpl') {
        my $bug_id = $vars->{'bugid'};
        my $bug = Bugzilla::Bug->new($bug_id);
        my $groups = $bug->groups_in;
        if (grep($_->{secure_mail}, @$groups)) {
            $vars->{'encrypt'} = 1;
        }
    }
    elsif ($file eq 'account/password/forgotten-password.txt.tmpl') {
        my $groups = $vars->{'user'}->groups;
        if (grep($_->{secure_mail}, @$groups)) {
            $vars->{'encrypt'} = 1;
        }      
    }
}

# Detect the header in the email which says that we need to encrypt, and do so.
sub mailer_before_send {
    my ($self, $args) = @_;
    
    my $email = $args->{email};
    if (my $user_id = $email->header('X-Bugzilla-SecureMail-Encrypt')) {

        my $bug_id;
        my $old_subject = $email->header('Subject');
        if ($bug_id = $email->header('X-Bugzilla-Bug-Id')) {
            my $new_subject = $old_subject;
            # This won't work if somebody's changed the Subject format.
            # However, as we don't easily know the value this installation 
            # is using for the word "bug", we have to adopt a 'modify' rather
            # than a 'replace' strategy.
            $new_subject =~ s/($bug_id\])\s+(.*)$/$1 (Secure bug updated)/;
            $email->header_set('Subject', $new_subject);
        }

        my $user = new Bugzilla::User($user_id);
        my $key = $user->{public_key};
        
        # S/MIME Keys must be in PEM format (Base64-encoded X.509)
        # PGP keys must be ASCII-armoured.
        if ($key && $key =~ /PUBLIC KEY/) {
            # PGP Encryption
            my $body = $email->body;
            if ($bug_id) {
                # Subject gets placed in the body so it's encrypted
                $body = "Subject: $old_subject\n\n" . $body;
            }
            
            my $pubring = new Crypt::OpenPGP::KeyRing(Data => $key);
            my $pgp = new Crypt::OpenPGP(PubRing => $pubring);
            
            # "@" matches every key in the public key ring, which is fine, 
            # because there's only one key in our keyring.
            my $encrypted = $pgp->encrypt(
                Data => $body, Recipients => "@", Armour => 1);
            if (defined $encrypted) {
                $email->body_set($encrypted);
            }
            else {
                $email->body_set('Error during Encryption: ' . $pgp->errstr);
            }
        }
        elsif ($key && $key =~ /BEGIN CERTIFICATE/) {
            # S/MIME encryption
            my $smime = Crypt::SMIME->new();
            my $encrypted;
            
            eval {
                $smime->setPublicKey([$key]);                
                $encrypted = $smime->encrypt($email->as_string());
            };
            
            if (!$@) {      
                # We can't replace the Email::MIME object, so we have to swap
                # out its component parts.
                my $enc_obj = new Email::MIME($encrypted);
                $email->header_obj_set($enc_obj->header_obj());
                $email->body_set($enc_obj->body());
            }
            else {
                # Delete the entire message body and append an error.
                $email->body_set('Error during Encryption: ' . $@);
            }
        }
        else {
            # No encryption key provided
            my $template = Bugzilla->template;
            my $message;
            my $vars = {
              'urlbase' =>    correct_urlbase(),
              'bug_id' =>     $bug_id,
              'maintainer' => Bugzilla->params->{'maintainer'}
            };
            
            $template->process('account/email/encryption-required.txt.tmpl',
                               $vars, \$message)
              || ThrowTemplateError($template->error());
            
            $email->body_set($message);
        }
    }
}

__PACKAGE__->NAME;
