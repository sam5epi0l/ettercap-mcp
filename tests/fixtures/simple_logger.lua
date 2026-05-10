local ettercap = require("ettercap")

function packet_handler(packet)
    local data = packet:get_data()
    if data:find("GET ") then
        local url = data:match("GET ([^%s]+)")
        if url then
            ettercap.ui_msg("Lua Sniffer: Observed GET request for " .. url .. "\n")
        end
    end
end

ettercap.register_hook("packet_handler", packet_handler)
