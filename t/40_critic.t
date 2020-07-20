use Test::More;

plan( skip_all => 'Test::Perl::Critic required to criticise code' )
  unless eval { require Test::Perl::Critic; 1 };


Test::Perl::Critic::all_critic_ok();
