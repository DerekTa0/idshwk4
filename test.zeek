global a:set[addr];
global b:set[addr];
global all:table[addr] of double;
global err:table[addr] of double;
global url:table[addr] of set[string];
event zeek_init()
	{
	#创建Reducer，统计数据中出现404和正常的个数
	local res_all=SumStats::Reducer($stream="all response",$apply=set(SumStats::SUM));
	local res_404 = SumStats::Reducer($stream="404 response" ,$apply=set(SumStats::SUM));
	
	SumStats::create([$name="all response",
					$epoch=600secs,
					$reducers=set(res_all),
					$epoch_result(ts:time,key:SumStats::Key,result:SumStats::Result)=
					{
						local res=result["all response"];
						if(!(key$host in a))
						{
							add a[key$host];
							all[key$host]=res$sum;
						}
						else
						{
							all[key$host]+=res$sum;
						}
					}]);
	SumStats::create([$name="404 response",
					$epoch=600secs,
					$reducers=set(res_404),
					$epoch_result(ts:time,key:SumStats::Key,result:SumStats::Result)=
					{
						local res = result["404 response"];
						if(!(key$host in b)) 
						{
							add b[key$host];
							err[key$host]=res$sum;
							url[key$host]=set();
						}
						else
							err[key$host]+=res$sum;
						if(!(key$str in url[key$host]))
						{
							add url[key$host][key$str];
						}
					}]);
	}

event http_reply(c: connection, version: string, code: count, reason:string)
	{
	SumStats::observe("all response", SumStats::Key($host=c$id$orig_h, $str=c$http$uri), SumStats::Observation($num=1));
	if (code == 404)
		SumStats::observe("404 response", SumStats::Key($host=c$id$orig_h, $str=c$http$uri), SumStats::Observation($num=1));
	}

event zeek_done()
	{
		for (i in a)
		{
			if((i in b)&&(err[i]>2)&&(err[i]/all[i]>0.2)&&(|url[i]|/err[i]>0.5))
				print fmt("%s is a scanner with %.0f scan attemps on %d urls", i, err[i], |url[i]|);
		}
	}
