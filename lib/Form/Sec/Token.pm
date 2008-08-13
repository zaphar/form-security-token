use Digest::SHA1;
use Data::GUID;

package Form::Sec::Token;

our $VERSION = '0.01';

=head1 NAME

Form::Sec::Token - protection against XSRF (Cross Site Request Forgery)

=head1 VERSION

version 0.01

=head1 SYNOPSIS

    my $FSToken = Form::Sec::Token->new(ident => $session_key,
                                        expire => 'expiration date');
    my $token = $FSToken->token();
    my $digest = $FSToken->digest();
    ## store the digest somewhere in session
    ...
    ## build your form with the expiration and token as hiden fields
    $form .= $FSToken->form_fields('XSRF_') . '</form>';
    ...
    ## The form gets posted and you create a new $FSToken with the posted fields
    my $newFSToken = Form::Sec::Token->new(ident => $session_key,
                                           expire => $form_expire_field,
                                           token => $form_token_field);
    ## retrieve the digest you stored in the session
    ...
    if ($newFSToken->match_digest($digest_from_session)) {
        ## continue
    } else {
        ## ack you just intercepted an XSRF attack
        ## maybe you should log it?
    }


=head1 CONSTRUCTORS
 
=head2 new

object constructor. requires an ident => $identifier pair in the args.
Optionally can have expire => 'expiration value' pair also in the args
Also Optionally can have token => $token specified in args.

=cut

sub new {
    my $self = shift;
    my %opts = @_;
    my $token = $opts{token} || Data::GUID->new()->as_base64();
    return bless {ident => sub { return $opts{ident} },
                  expire => sub { $opts{expire} },
                  token => sub { $token }
                 }, $self;

}

=head1 ATTRIBUTES

=head2 ident

Immutable: returns the identifier attribute

=cut

sub ident {
    return shift->{ident}->();
}

=head2 expire 

Immutable: returns the expire attribute

=cut

sub expire {
    return shift->{expire}->();
}

=head2 token

Immutable: returns the token attribute

=cut

sub token {
    return shift->{token}->();
}

=head1 METHODS

=head2 digest

returns the digest of the stored data

=cut

sub digest {
    my $self = shift;
    return $self->_mk_digester()->( $self->token() );
}

=head2 match_token

takes a token as an argument and compares it to the stored token. 
Returns true or false
this is useless I might just remove it. - jwall

=cut

sub match_token {
    my $self = shift;
    my $token = shift;
    return $token eq $self->token();
}

=head2 match_digest

takes a digest as an argument and compares it to its own digest. 
Returns true or false

=cut

sub match_digest {
    my $self = shift;
    my $digest = shift;
    return $digest eq $self->digest();

}

=head2 form_fields

takes an optional $prefix argument
outputs the hidden form fields to include in your html form
prefixing the field names with the prefix if specified

=cut

sub form_fields {
    my $self = shift;
    my $prefix = shift;
    my $string = "<input type='hidden' name='$prefix"."expire' id='$prefix"."expire' value='".$self->expire()."' />";
    $string .= "<input type='hidden' name='$prefix"."token' id='$prefix"."token' value='".$self->token()."' />";
    return $string;
}

sub _mk_digester {
    my $self = shift;
    return sub {
        my $token = shift;
        my $sha1 = Digest::SHA1->new();
        $sha1->add(join '|', $self->ident(), $token, $self->expire);
        return $sha1->b64digest();
    }
}

1;
