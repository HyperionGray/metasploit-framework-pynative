require 'spec_helper'

# Payload test generator - creates tests programmatically instead of hardcoding them
class PayloadTestGenerator
  def self.generate_tests(modules_pathname)
    # Define payload configurations
    payload_configs = [
      {
        name: 'aix/ppc/shell_bind_tcp',
        ancestors: ['singles/aix/ppc/shell_bind_tcp'],
        dynamic_size: false
      },
      {
        name: 'aix/ppc/shell_find_port',
        ancestors: ['singles/aix/ppc/shell_find_port'],
        dynamic_size: false
      },
      {
        name: 'aix/ppc/shell_interact',
        ancestors: ['singles/aix/ppc/shell_interact'],
        dynamic_size: false
      },
      {
        name: 'aix/ppc/shell_reverse_tcp',
        ancestors: ['singles/aix/ppc/shell_reverse_tcp'],
        dynamic_size: false
      },
      {
        name: 'apple_ios/aarch64/meterpreter_reverse_http',
        ancestors: ['stages/apple_ios/aarch64/meterpreter', 'stagers/apple_ios/aarch64/reverse_http'],
        dynamic_size: false
      }
      # Add more payload configurations as needed
    ]

    # Generate tests for each payload
    payload_configs.each do |config|
      create_payload_test(config, modules_pathname)
    end
  end

  private

  def self.create_payload_test(config, modules_pathname)
    context config[:name] do
      it_should_behave_like 'payload cached size is consistent',
                            ancestor_reference_names: config[:ancestors],
                            dynamic_size: config[:dynamic_size],
                            modules_pathname: modules_pathname,
                            reference_name: config[:name]
    end
  end
end

RSpec.describe 'modules/payloads', :content do
  modules_pathname = Pathname.new(__FILE__).parent.parent.parent.join('modules')

  include_context 'untested payloads', modules_pathname: modules_pathname

  # Generate tests programmatically
  PayloadTestGenerator.generate_tests(modules_pathname)
end