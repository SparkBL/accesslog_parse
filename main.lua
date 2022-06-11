local open = io.open

local function dump(o)
  if type(o) == 'table' then
     local s = '{ '
     for k,v in pairs(o) do
        if type(k) ~= 'number' then k = '"'..k..'"' end
        s = s .. '['..k..'] = ' .. dump(v) .. ',\n'
     end
     return s .. '} '
  else
     return tostring(o)
  end
end


local function count_non_trues(t)
  local c = 0
  for _,v in pairs(t) do
    if v then c= c+1 end
  end
  return c
end


function table.slice(tbl, first, last, step)
  local sliced = {}

  for i = first or 1, last or #tbl, step or 1 do
    sliced[#sliced+1] = tbl[i]
  end
  return sliced
end


local function get_top_10_ips(ips)
  local logtable = {}
  local sorted = {}
  for _,log in pairs(ips) do logtable[log['ip']] = (logtable[log['ip']] or 0) + 1 end 
  for k, v in pairs(logtable) do table.insert(sorted,{k,v}) end
  table.sort(sorted, function(a,b) return a[2] > b[2] end)
  logtable = {}
  local cn = 0
  for k, v in ipairs(sorted) do
    if cn > 10 then break end
    logtable[k] = {v[1],v[2]}
    cn = cn+1
  end
  return logtable
end


local function lines_from(path)
  local lines = {}
  for line in io.lines(path) do 
    local stru = {ip = string.match(line,"^%d+.%d+.%d+.%d+"),local_time = string.match(line,"%d+/%D+/%d+:%d+:%d+:%d+")}
    stru['status_code'],stru['bytes_send'] = string.match(line, "(%d+)%s(%d+)")
    stru['path'],stru['referer'],stru['user_agent']=string.match(line,"\"(.*)\"[^%.]+\"(.*)\"[^%.]+\"(.*)\"")
    lines[#lines + 1] = stru
  end
  return lines
end


local function read_log(path)
  local num = 1
  for line in io.lines(path) do 
    local susps = {}
    susps[1] = string.match(line, "\"%s(4%d+)%s") ~= nil
    susps[2] = string.match(line, "(Mozilla)") == nil
    susps[3] = string.match(line, "(OPTIONS)") ~= nil
    susps[4] = string.match(line, "%d+%s(\"%p\")%s\"") ~= nil
    susps[5] = string.match(line,"\"%u+%s/%w+%.%w+%.%w+") ~=nil
    --print(susps[1],susps[2],susps[3],susps[4],susps[5])
    if count_non_trues(susps)>1 then print(num,line) end
    num = num+1
  end
end




local function main()
  if arg[1] then
    local lg = lines_from(arg[1])
    print("Top 10 IPs:")
    for _,v in ipairs(get_top_10_ips(lg)) do print(v[1],v[2]) end
    print("\n\nSuspicous requests:")
    read_log(arg[1])
 else
  print("Provide path to accesslog")
end
end

main()