graph TD
    start[LookingGlass Start]
    state{Live/PCAP}
    user_param[Load User Parameters]
    start--> user_param
    user_param -->state
    adapt[Start Sniffing]
    state--> |Live| adapt
    cold[Read PCAP File]
    state--> |PCAP| cold
    threading[Create Thread for Each Packet]
    cold-->threading
    adapt-->threading
    ident{Is HTTPRequest?}
    threading-->ident
    params[GetParameters]
    bin[DoRawSearch]
    ident-->|HTTPRequest|params
    ident-->|Binary|bin
    vars[Encodings Search]
    decode[DecodeParams]
    params-->decode
    bin-->vars
    decode-->vars
    join[JoinThreads]
    vars-->join
    csv[WriteCSV]
    html[WriteHTML]
    join-->csv
    match{Matches ?}
    csv-->match
    match-->|Yes|html
    match-->|No|Quit
    html-->Quit

    
