firewall_test:- open(".//Rule1.txt",read,Str1), open(".//Packet.txt",read,Str2),
       read_string(Str1,2000,String1), read_string(Str2,2000,String2),
       close(Str1),close(Str2),
       split_string(String1,"\n","\n",L1),
       split_string(String2,"\n","\n",L2),(
                                                    (   firewall(L1,L2),write("Accepted"));
                                                     (  not( firewall(L1,L2)),write("Denied"))
                                        ).

%firewall([L],L2) :- fun(L,L2).
firewall([],L2).
firewall([X|Y],L2) :- fun(X,L2),firewall(Y,L2).


fun(R,P):-
   split_string(R," ","",Q),
    [R1|Z1]=Q,
    [R2|Z2]=Z1,

    [X1|Y1]=P,
    [X2|Y2]=Y1,
    [X3|Y3]=Y2,
    [X4|Y4]=Y3,
    [X5|Y5]=Y4,
    [X6|Y6]=Y5,
    [X7|Y7]=Y6,
    [X8|Y8]=Y7,

    (
                (=(R2,"adapter"), adapter(Q,X1) );
                (=(R2,"ether"),ether(Q,X2));
                (=(R2,"ip"),ipv4(Q,X3));
                (=(R2,"ipv6"), ipv6(Q,X4));
                (=(R2,"tcp"),tcp(Q,X5));
                (=(R2,"udp"), udp(Q,X6));
                (=(R2,"icmp"), icmp(Q,X7));
                (=(R2,"icmpv6"), icmpv6(Q,X8) )

    ).


adapter(R,V):-

    ([R1|Z] =R),
    ([R2|Y1]=Z),
    ([R3|Y2]=Y1),
    (( =(R1,"accept"),comp(R3,V)); (=(R1,"deny"),not(comp(R3,V))))  .


ether(R,V):-
     split_string(V,";","",V1),

     [R1|Z1]=R,
     [R2|Z2]=Z1,
     [R3|Z3]=Z2,
     [R4|Z4]=Z3,
     [R5|Z5]=Z4,
     [R6|Z6]=Z5,
     [S1|W]=V1,
     [S2|W1]=W,

     (
         ( =(R1,"accept"),comp(R4,S1),comp(R6,S2));(=(R1,"deny"),(not(comp(R4,S1));not(comp(R6,S2))))

     ).


ipv6(R,V):-

     split_string(V,";","",V1),

     [R1|Z1]=R,
     [R2|Z2]=Z1,
     [R3|Z3]=Z2,
     [R4|Z4]=Z3,
     [R5|Z5]=Z4,
     [R6|Z6]=Z5,
     [R7|Z7]=Z6,
     [R8|Z8]=Z7,
     [R9|Z9]=Z8,
     [R10|Z10]=Z9,

     [S1|W]=V1,
     [S2|W1]=W,
     [S3|W2]=W1,

     (
         ( =(R1,"accept"),comp(R5,S1),comp(R8,S2),comp(R10,S3));
         (
             =(R1,"deny"),(
               not(comp(R5,S1));not(comp(R8,S2));not(comp(R10,S3))
          )
         )

     ).

ipv4(R,V):-

     split_string(V,";","",V1),

     [R1|Z1]=R,
     [R2|Z2]=Z1,
     [R3|Z3]=Z2,
     [R4|Z4]=Z3,
     [R5|Z5]=Z4,
     [R6|Z6]=Z5,
     [R7|Z7]=Z6,
     [R8|Z8]=Z7,
     [R9|Z9]=Z8,
     [R10|Z10]=Z9,

     [S1|W]=V1,
     [S2|W1]=W,
     [S3|W2]=W1,

     (
         ( =(R1,"accept"),comp(R5,S1),comp(R8,S2),comp(R10,S3));
         (
             =(R1,"deny"),(
               not(comp(R5,S1));not(comp(R8,S2));not(comp(R10,S3))
          )
         )

     ).



tcp(R,V):-
split_string(V,";","",V1),
[R1|Z1] = R,
[R2|Z2] = Z1,
[R3|Z3] = Z2,
[R4|Z4] = Z3,
[R5|Z5] = Z4,
[R6|Z6] = Z5,
[R7|Z7] = Z6,
[R8|Z8] = Z7,

[S1|W] = V1,
[S2|W1] = W,

((=(R1,"accept"), comp(R5,S1), comp(R8,S2));(=(R1,"deny"),(not(comp(R5,S1));not(comp(R8,S2))))).

udp(R,V):-
split_string(V,";","",V1),
[R1|Z1] = R,
[R2|Z2] = Z1,
[R3|Z3] = Z2,
[R4|Z4] = Z3,
[R5|Z5] = Z4,
[R6|Z6] = Z5,
[R7|Z7] = Z6,
[R8|Z8] = Z7,

[S1|W] = V1,
[S2|W1] = W,

((=(R1,"accept"), comp(R5,S1), comp(R8,S2));(=(R1,"deny"),(not(comp(R5,S1));not(comp(R8,S2))))).


icmp(R,V):-
split_string(V,";","",V1),
[R1|Z1] = R,
[R2|Z2] = Z1,
[R3|Z3] = Z2,
[R4|Z4] = Z3,
[R5|Z5] = Z4,
[R6|Z6] = Z5,

[S1|W] = V1,
[S2|W1] = W,

((=(R1,"accept"), comp(R4,S1), comp(R6,S2));(=(R1,"deny"),(not(comp(R4,S1));not(comp(R6,S2))))).

icmpv6(R,V):-
split_string(V,";","",V1),
[R1|Z1] = R,
[R2|Z2] = Z1,
[R3|Z3] = Z2,
[R4|Z4] = Z3,
[R5|Z5] = Z4,
[R6|Z6] = Z5,

[S1|W] = V1,
[S2|W1] = W,

((=(R1,"accept"), comp(R4,S1), comp(R6,S2));(=(R1,"deny"),(not(comp(R4,S1));not(comp(R6,S2))))).




comp(S1,P):-
         (atom_codes(S1,K1),member(X3,K1),char_code(",",X3), char_code(P,P1),member(P,L2),split_string(S1,",","",L2));
    =(S1,P);=(S1,"any");
  (atom_codes(S1,K1),member(X3,K1),char_code("-",X3),split_string(S1,"-","",N),[E1|Z1]=K1,[E2|Z2] = Z1,[E3|Z3] = Z2,
  between(E1,E3,P1)).

