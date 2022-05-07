@load base/frameworks/sumstats
event http_reply(c:connection,version:string,code:count,reason:string)
{
    SumStats::observe("resp",SumStats::Key($host=c$id$orig_h),SumStats::Observation($num=1));
    if(code==404)
    {
        SumStats::observe("resp_404",SumStats::Key($host=c$id$orig_h),SumStats::Observation($num=1));
        SumStats::observe("unique_resp_404",SumStats::Key($host=c$id$orig_h),SumStats::Observation($str=c$http$uri));    
    }
}

event zeek_init()
{
    local r=SumStats::Reducer($stream="resp",$apply=set(SumStats::SUM));
    local r404=SumStats::Reducer($stream="resp_404",$apply=set(SumStats::SUM));
    local ur404=SumStats::Reducer($stream="unique_resp_404",$apply=set(SumStats::UNIQUE));
    SumStats::create([$name="idshwk4",$epoch=10min,$reducers=set(r,r404,ur404),$epoch_result(ts:time,key:SumStats::Key,result:SumStats::Result)=
    {
        local r1=result["resp"];
        local r2=result["resp_404"];
        local r3=result["unique_resp_404"];
        if(r2$sum>2)
        {
            if(r2$sum/r1$sum>0.2)
            {
                if(r3$unique/r2$sum>0.5)
                {
                    print fmt("%s is a scanner with %.0f scan attemps on %.0f urls",key$host,r2$sum,r3$unique);
                }
            }
        }
    }]);
}
