<%
    freenas_version = dispatcher.call_sync('system.info.version')
    motd = dispatcher.call_sync('system.advanced.get_config')['motd']
    static_output = """Welcome to: {0}
To make configuration changes, type 'cli' and use the CLI command set.
Any configuration changes used outside of the FreeNAS CLI are not saved to the configuration database.
    """.format(freenas_version)
%>\

${static_output}

${motd} 
