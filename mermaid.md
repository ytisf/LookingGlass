graph TD

  subgraph looking_glass.py
    start[LookingGlass Start]
    state{Live/PCAP}
    user_param[Load User Parameters]
    start--> user_param
    user_param -->state
    adapt[Start Sniffing]
    state--> |Live| adapt
    cold[Read PCAP File]
    state--> |PCAP| cold
    end

  subgraph tester.py
    vars[Encodings Search]
    bin[DoRawSearch]
    httpsearch[ParamsMatching]
    httpsearch-->vars
    bin-->vars
    end

  subgraph packets_do.py
    threading[Create Thread for Each Packet]
    cold-->threading
    adapt-->threading
    ident{Is HTTPRequest?}
    threading-->ident
    params[GetParameters]
    ident-->|HTTPRequest|params
    ident-->|Binary|bin
    decode[DecodeParams]
    params-->decode
    decode-->httpsearch
    end

  subgraph looking_glass.py
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
    end
