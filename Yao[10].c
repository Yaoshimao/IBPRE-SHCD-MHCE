//RIB-CPRE-CE for secure cloud sharing
//Xiong et al. 2019, multi-hop IBCPRE for authorization

#include<pbc.h>
#include<pbc_time.h>
#define CHISHU 1
int main()
{
	//variants declear
	pairing_t pairing; 
	element_t g,h,h1,h2,h3,h4,a,b,c,pair_a,pair_b,par_c;   
	element_t Ai1,Ai2,Ai3,Bi1,Bi2,Bi3,Di1,Di2,Di3,I;
	element_t ti,xi,yi,zi,tempi;
	element_t Aj1,Aj2,Aj3,Bj1,Bj2,Bj3,Dj1,Dj2,Dj3,J;
	element_t tj,xj,yj,zj,tempj;
	element_t w,dk1,dk2,dk3,drk1,drk2,drk3,temp_drk1,temp_drk2;
	element_t m1,x,ssk,svk,haxi_svk,Ci0,Ci1,Ci2,Ci3,Ci4,Ci5,Ci6,haxi_Ci,r; //x=ssk
	element_t temp1,temp2,p1;   
	element_t Cj0,Cj1,Cj2,Cj3,Cj4,Cj5,Cj6;
	element_t nti,nxi,nyi,nzi,ntempi;    //new identity of user I
	element_t nAi1,nAi2,nAi3,nBi1,nBi2,nBi3,nDi1,nDi2,nDi3,nI;
	element_t uk1,uk2,urk1,urk2,temp_urk1,temp_urk2;
	element_t nCi0,nCi1,nCi2,nCi3,nCi4,nCi5,nCi6;  //for updated ciphertext nC_I

	int check=0;
	double time1,time2,time3;
	double ts[CHISHU],tkg1[CHISHU],tkg2[CHISHU],tkg3[CHISHU],te[CHISHU],td1[CHISHU],td2[CHISHU],td3[CHISHU],trkg1[CHISHU],trkg2[CHISHU],tre1[CHISHU],tre2[CHISHU];
	double T_s,T_kg1,T_kg2,T_kg3,T_e,T_d1,T_d2,T_d3,T_rkg1,T_rkg2,T_re1,T_re2;
	int i;
	T_s=0;T_kg1=0;T_kg2=0;T_kg3=0;T_e=0;T_d1=0;T_d2=0;T_d3=0;T_rkg1=0;T_rkg2=0;T_re1=0;T_re2=0;

	//variants init
	a_param_input(pairing); //input type-A parameters
	element_init_G1(g,pairing);     
	element_init_G1(h,pairing);
	element_init_G1(h1,pairing);
	element_init_G1(h2,pairing);
	element_init_G1(h3,pairing);
	element_init_G1(h4,pairing);
	element_init_GT(pair_a,pairing);
	element_init_GT(pair_b,pairing);
	element_init_G1(par_c,pairing);
	element_init_Zr(a,pairing);
	element_init_Zr(b,pairing);
	element_init_Zr(c,pairing);      //Setup
	element_init_Zr(Ai1,pairing);
	element_init_G1(Ai2,pairing);
	element_init_G1(Ai3,pairing);
	element_init_Zr(Bi1,pairing);
	element_init_Zr(Bi2,pairing);
	element_init_Zr(Bi3,pairing);
	element_init_G1(Di1,pairing);
	element_init_G1(Di2,pairing);
	element_init_G1(Di3,pairing);
	element_init_Zr(I,pairing);    
	element_init_Zr(ti,pairing);
	element_init_Zr(xi,pairing);
	element_init_Zr(yi,pairing);
	element_init_Zr(zi,pairing);   
	element_init_Zr(tempi,pairing);   //KeyGen for identity I,tempi->b*I->a+b*I
	element_init_Zr(Aj1,pairing);
	element_init_G1(Aj2,pairing);
	element_init_G1(Aj3,pairing);
	element_init_Zr(Bj1,pairing);
	element_init_Zr(Bj2,pairing);
	element_init_Zr(Bj3,pairing);
	element_init_G1(Dj1,pairing);
	element_init_G1(Dj2,pairing);
	element_init_G1(Dj3,pairing);
	element_init_Zr(J,pairing);
	element_init_Zr(tj,pairing);
	element_init_Zr(xj,pairing);
	element_init_Zr(yj,pairing);
	element_init_Zr(zj,pairing);
	element_init_Zr(tempj,pairing);    //KeyGen for identity J, tempj->b*J->a+b*J
	element_init_Zr(w,pairing);        //condition
	element_init_Zr(dk1,pairing);
	element_init_Zr(dk2,pairing);
	element_init_Zr(dk3,pairing);
	element_init_Zr(drk1,pairing);
	element_init_G1(drk2,pairing);
	element_init_G1(drk3,pairing);
	element_init_Zr(temp_drk1,pairing);
	element_init_G1(temp_drk2,pairing);    //ReKeyGen  from identity I to J
	element_init_GT(m1,pairing);
	element_init_Zr(x,pairing);
	element_init_Zr(ssk,pairing);
	element_init_G1(svk,pairing);
	element_init_Zr(haxi_svk,pairing);     //hash(svk) in Zq
	element_init_G1(Ci0,pairing);
	element_init_G1(Ci1,pairing);
	element_init_GT(Ci2,pairing);
	element_init_GT(Ci3,pairing);
	element_init_G1(Ci4,pairing);
	element_init_G1(Ci5,pairing);
	element_init_G1(Ci6,pairing);
	element_init_G1(haxi_Ci,pairing);      //hash(w,Ci1,Ci2,Ci4,Ci5) in G1
	element_init_Zr(r,pairing);
	element_init_GT(temp1,pairing);     //for verification
	element_init_GT(temp2,pairing);
	element_init_GT(p1,pairing);        //Decrypting for ciphertext to get plaintext p1
	element_init_G1(Cj0,pairing);
	element_init_G1(Cj1,pairing);
	element_init_GT(Cj2,pairing);
	element_init_GT(Cj3,pairing);
	element_init_G1(Cj4,pairing);
	element_init_G1(Cj5,pairing); 
    	element_init_G1(Cj6,pairing);   //re-encrypted ciphertext Cj has the same form as Ci
	element_init_Zr(nI,pairing);    
	element_init_Zr(nti,pairing);
	element_init_Zr(nxi,pairing);
	element_init_Zr(nyi,pairing);
	element_init_Zr(nzi,pairing);   
	element_init_Zr(ntempi,pairing);   //KeyGen for new identity nI, ntempi->b*nI->a+b*nI
	element_init_Zr(nAi1,pairing);
	element_init_G1(nAi2,pairing);
	element_init_G1(nAi3,pairing);
	element_init_Zr(nBi1,pairing);
	element_init_Zr(nBi2,pairing);
	element_init_Zr(nBi3,pairing);
	element_init_G1(nDi1,pairing);
	element_init_G1(nDi2,pairing);
	element_init_G1(nDi3,pairing);
	element_init_Zr(uk1,pairing);   //generate update re-encryption key urk_(I->nI)
	element_init_Zr(uk2,pairing);
	element_init_Zr(urk1,pairing);
	element_init_G1(urk2,pairing);
	element_init_Zr(temp_urk1,pairing);
	element_init_G1(temp_urk2,pairing);   
	element_init_G1(nCi0,pairing);   //updated ciphertext nC_I
	element_init_G1(nCi1,pairing);
	element_init_GT(nCi2,pairing);
	element_init_GT(nCi3,pairing);
	element_init_G1(nCi4,pairing);
	element_init_G1(nCi5,pairing);
	element_init_G1(nCi6,pairing);

	//if the pairing is bot symmetric, abort
	if(!pairing_is_symmetric(pairing))
	{
		fprintf(stderr,"only works with symmetric pairing\n");
		exit(1);
	}
	
	for(i=0;i<CHISHU;i++)     //cycle begin
	{

	//system init
//	printf("--------Setup-------\n");
	time1=get_time();
	element_random(a);
	element_random(b);
	element_random(c);
	element_random(g);
	element_random(h);
	element_random(h1);
	element_random(h2);
	element_random(h3);
	element_random(h4);
	pairing_apply(pair_a,g,h,pairing);
	element_pow_zn(pair_b,pair_a,b);   //pair_b=e(g,h)^b
	element_pow_zn(pair_a,pair_a,a);   //pair_a=e(g,h)^a
	element_pow_zn(par_c,g,c);         //par_c=g^c
	time2=get_time();
	ts[i]=time2-time1;
//	printf(">>>The master secret key msk = (a,b,c).\n");
//	printf(">>>The system parameters par = (q,g,h,G,GT,h1,h2,h3,h4,pair_a,pair_b,par_c,Sig).\n\n");
//	printf(">>>the time of setup is: %fs\n\n",ts[i]);

	//generation of key pair for user i and user j
//	printf("----------Key Generation---------\n");
	element_random(I);    //identity of user i
	time1=get_time();
	element_random(ti);
	element_random(xi);
	element_random(yi);
	element_random(zi);
	element_mul(tempi,b,I);
	element_add(tempi,a,tempi);   //tempi=a+bI
	element_add(Ai1,c,ti);
	element_div(Ai1,Ai1,tempi);  //Ai1=(c+t)/(a+bI)
	element_pow_zn(Ai2,h,ti);
	element_pow_zn(Ai3,g,ti);
	element_add(Bi1,a,xi);
	element_div(Bi1,Bi1,tempi);
	element_add(Bi2,b,yi);
	element_div(Bi2,Bi2,tempi);
	element_div(Bi3,zi,tempi);
	element_pow_zn(Di1,h,xi);
	element_pow_zn(Di2,h,yi);
	element_pow_zn(Di3,h,zi);
	time2=get_time();
	tkg1[i]=time2-time1;
//	printf("the time of generating private key of identity i is %f second.\n",tkg1[i]);
//	byte_p=element_length_in_bytes(Ai1)+element_length_in_bytes(Ai2)+element_length_in_bytes(Ai3);
//	byte_p=byte_p+element_length_in_bytes(Bi1)+element_length_in_bytes(Bi2)+element_length_in_bytes(Bi3);
//	byte_p=byte_p+element_length_in_bytes(Di1)+element_length_in_bytes(Di2)+element_length_in_bytes(Di3);
//	printf("The private key of user i is ski = (Ai1,Ai2,Ai3,Bi1,Bi2,Bi3,Di1,Di2,Di3).\n");
//	printf("The length of the private key of user i is %d.\n",byte_p);

	//generation of the key pair of user j
	element_random(J);  //identity of user j
	time1=get_time();
	element_random(tj);
	element_random(xj);
	element_random(yj);
	element_random(zj);
	element_mul(tempj,b,J);
	element_add(tempj,a,tempj);   //tempj=a+bJ
	element_add(Aj1,c,tj);
	element_div(Aj1,Aj1,tempj);  //Aj1=(c+t)/(a+bJ)
	element_pow_zn(Aj2,h,tj);
	element_pow_zn(Aj3,g,tj);
	element_add(Bj1,a,xj);
	element_div(Bj1,Bj1,tempj);
	element_add(Bj2,b,yj);
	element_div(Bj2,Bj2,tempj);
	element_div(Bj3,zj,tempj);
	element_pow_zn(Dj1,h,xj);
	element_pow_zn(Dj2,h,yj);
	element_pow_zn(Dj3,h,zj);
	time2=get_time();
	tkg2[i]=time2-time1;
//	printf("the time of generating private key of identity i is %f second.\n",tkg2[i]);
//	printf("The private key of user j is skj = (Aj1,Aj2,Aj3,Bj1,Bj2,Bj3,Dj1,Dj2,Dj3).\n\n");

	//generation of delegation re-encryption key 
//	printf("-----------Delegation Re-encryption Key Generation--------\n");
	element_random(w);
	time1=get_time();
	element_random(dk1);
	element_random(dk2);
	element_random(dk3);
	element_mul(temp_drk1,dk2,Bi3);
	element_add(temp_drk1,temp_drk1,Bi2);
	element_mul(temp_drk1,temp_drk1,J);
	element_mul(drk1,dk1,Bi3);
	element_add(drk1,drk1,Bi1);
	element_add(drk1,drk1,temp_drk1);
	element_pow_zn(temp_drk2,Di3,dk2);
	element_mul(temp_drk2,Di2,temp_drk2);
	element_pow_zn(temp_drk2,temp_drk2,J);
	element_pow_zn(drk2,Di3,dk1);
	element_mul(drk2,Di1,drk2);
	element_mul(drk2,drk2,temp_drk2);
	element_pow_zn(temp_drk2,h1,w);
	element_mul(temp_drk2,temp_drk2,h2);
	element_pow_zn(temp_drk2,temp_drk2,dk3);
	element_mul(drk2,drk2,temp_drk2);
	element_pow_zn(drk3,g,dk3);
	time2=get_time();
	trkg1[i]=time2-time1;
//	printf("the time of generating private key of identity I is %f second.\n",trkg1[i]);
//	byte_p=element_length_in_bytes(drk1)+element_length_in_bytes(drk2)+element_length_in_bytes(drk3);
//	printf("The re-encryption key from user I to J is drk = (drk1,drk2,drk3).\n");
	
		
	//Encryption of ciphertext
//	printf("---------------Enc---------------------\n");
	element_random(m1);
//	element_printf("The plaintext to be encrypted is m1 = %B.\n",m1);
	time1=get_time();
	element_random(x);
	element_set(ssk,x);
	element_pow_zn(svk,g,ssk);
	element_set(Ci0,svk);                 //Ci0=svk
	element_random(r);
	element_pow_zn(Ci1,g,r);
	pairing_apply(Ci2,par_c,h,pairing);     //e(g^c,h)
	element_pow_zn(Ci2,Ci2,r); 
	element_mul(Ci2,m1,Ci2);             //Ci2=e(g,h)^(c*r)
	element_pow_zn(Ci3,pair_b,I);           //(e(g,h)^b)^I
	element_mul(Ci3,pair_a,Ci3);          //(e(g,h)^a)*(e(g,h)^b)^I=e(g,h)^(a+bI)
	element_pow_zn(Ci3,Ci3,r);           //Ci3=e(g,h)^((a+bI)*r)
	element_pow_zn(Ci4,h1,w);
	element_mul(Ci4,Ci4,h2);
	element_pow_zn(Ci4,Ci4,r);           //Ci4=(h1^w*h2)&r
	element_random(haxi_svk);
	element_pow_zn(Ci5,h3,haxi_svk);     
	element_mul(Ci5,Ci5,h4);
	element_pow_zn(Ci5,Ci5,r);         //Ci5=(h3^hash(svk)*h4)^r
	element_random(haxi_Ci);           //hash(w,C1,C2,C4,C5)
	element_pow_zn(Ci6,haxi_Ci,ssk);     //Signature is Sig(ssk,(w,Ci1,Ci2,Ci4,Ci5))
	time2=get_time();
	te[i]=time2-time1;
//	printf("the time of encrypting m1 is %f second.\n",te[i]);
//	byte_p=element_length_in_bytes(Ci0)+element_length_in_bytes(Ci1)+element_length_in_bytes(Ci2)+element_length_in_bytes(Ci3)+element_length_in_bytes(Ci4);
//	byte_p=byte_p+element_length_in_bytes(Ci5)+element_length_in_bytes(Ci6)+element_length_in_bytes(w);
//	printf("The length of the level-2 ciphertext is %d bytes.\n",byte_p);

	//decryption of original ciphertext Ci 
//	printf("-----------Dec original Ci--------\n");
	time1=get_time();
	//check the ciphertext
	pairing_apply(temp1,svk,haxi_Ci,pairing);    //e(svk,hash(Ci))=e(g^ssk,hash(Ci))
	pairing_apply(temp2,Ci6,g,pairing);            //e(g,Ci6)=e(g,hash(Ci)^ssk)
	if(!element_cmp(temp1,temp2))
		check=1;
	element_pow_zn(temp_drk2,h1,w);
	element_mul(temp_drk2,temp_drk2,h2);          //h1^w*h2
	pairing_apply(temp1,Ci1,temp_drk2,pairing);   //e(g^r,h1^w*h2)
	pairing_apply(temp2,g,Ci4,pairing);           //e(g,(h1^w*h2)^r)
	if(!element_cmp(temp1,temp2))
		check+=1;
	element_pow_zn(temp_drk2,h3,haxi_svk);
	element_mul(temp_drk2,temp_drk2,h4);
	pairing_apply(temp1,Ci1,temp_drk2,pairing);
	pairing_apply(temp2,g,Ci5,pairing);
	if(!element_cmp(temp1,temp2))
		check+=1;
	time3=get_time();
	if(check<3)
		printf("The verification of original ciphertext fails, please check the codes!\n");
	else
		{
//			printf("The original level-2 ciphertext is well-formed.\n");
			pairing_apply(temp1,Ci1,Ai2,pairing);     //e(g^r,h^ti)
			element_mul(p1,Ci2,temp1);                //p1=m*e(g,h)^(c*r)*e(g^r,h^ti)
			element_pow_zn(temp2,Ci3,Ai1);            //temp2=(e(g,h)^((a+b*I)*r))^((c+ti)/(a+b*I))
			element_div(p1,p1,temp2);                 //p1/temp2=m
			if(element_cmp(m1,p1))
				printf("Decryption of original ciphertext fails, please check the algorithm or codes!\n");
			else
				{
					time2=get_time();
					td1[i]=time2-time1;
//					printf("the time of decrypting original ciphertext m1 (without verification) is %f second.\n",td1[i]);
//					printf("Decryption of original ciphertext successess!\n");
//					element_printf("The decrypting plaintext p1 = %B.\n",p1);
				}
		}
//	printf("the time of ciphertext verification before original decryption is %f s\n\n",time3-time1);

	//re-encrypt ciphertext for delegation
//	printf("-------------delegation re-encryption-------------\n");
	time1=get_time();
	pairing_apply(temp1,svk,haxi_Ci,pairing);    //e(svk,hash(Ci))=e(g^ssk,hash(Ci))
	pairing_apply(temp2,Ci6,g,pairing);            //e(g,Ci6)=e(g,hash(Ci)^ssk)
	if(!element_cmp(temp1,temp2))
		check=1;
	element_pow_zn(temp_drk2,h1,w);
	element_mul(temp_drk2,temp_drk2,h2);          //h1^w*h2
	pairing_apply(temp1,Ci1,temp_drk2,pairing);   //e(g^r,h1^w*h2)
	pairing_apply(temp2,g,Ci4,pairing);           //e(g,(h1^w*h2)^r)
	if(!element_cmp(temp1,temp2))
		check+=1;
	element_pow_zn(temp_drk2,h3,haxi_svk);
	element_mul(temp_drk2,temp_drk2,h4);
	pairing_apply(temp1,Ci1,temp_drk2,pairing);
	pairing_apply(temp2,g,Ci5,pairing);
	if(!element_cmp(temp1,temp2))
		check+=1;
	time3=get_time();
	if(check<3)
		printf("Verification fails, please check the codes!\n");
	else
		{
//			printf("Verification successes!\n");
			element_set(Cj0,Ci0);
			element_set(Cj1,Ci1);
			element_set(Cj2,Ci2);
			pairing_apply(temp1,Ci4,drk3,pairing);   //e((h3^w*h4)^r,g^drk3)
			pairing_apply(temp2,Ci1,drk2,pairing);   //e(g^r,drk2)
			element_pow_zn(Cj3,Ci3,drk1);
			element_mul(Cj3,Cj3,temp1);
			element_div(Cj3,Cj3,temp2);
			element_set(Cj4,Ci4);
			element_set(Cj5,Ci5);
			element_set(Cj6,Ci6);
			time2=get_time();
			tre1[i]=time2-time1;
//			printf("the time of computing delegation ciphertext (without verification) is %f second.\n",tre1[i]);
		}
//	printf("the time of ciphertext verification before delegation transformation is %f s\n\n",time3-time1);

	//decryption of re-encrypted ciphertext Cj 
//	printf("-----------Dec2 for Cj--------\n");
	time1=get_time();
	pairing_apply(temp1,svk,haxi_Ci,pairing);    //e(svk,hash(Ci))=e(g^ssk,hash(Ci))
	pairing_apply(temp2,Cj6,g,pairing);            //e(g,Cj6)=e(g,hash(Ci)^ssk)
	if(!element_cmp(temp1,temp2))
		check=1;
	element_pow_zn(temp_drk2,h1,w);
	element_mul(temp_drk2,temp_drk2,h2);          //h1^w*h2
	pairing_apply(temp1,Cj1,temp_drk2,pairing);   //e(g^r,h1^w*h2)
	pairing_apply(temp2,g,Cj4,pairing);           //e(g,(h1^w*h2)^r)
	if(!element_cmp(temp1,temp2))
		check+=1;
	element_pow_zn(temp_drk2,h3,haxi_svk);
	element_mul(temp_drk2,temp_drk2,h4);
	pairing_apply(temp1,Cj1,temp_drk2,pairing);  //e(g^r,(h3^(svk)*h4))
	pairing_apply(temp2,g,Cj5,pairing);
	if(!element_cmp(temp1,temp2))
		check+=1;
	time3=get_time();
	if(check<3)
		printf("Verification fails, please check the codes!\n");
	else
		{
//			printf("The re-encrypted ciphertext is well-formed.\n");
			pairing_apply(temp1,Cj1,Aj2,pairing);
			element_mul(p1,Cj2,temp1);
			element_pow_zn(temp2,Cj3,Aj1);
			element_div(p1,p1,temp2);
			if(element_cmp(m1,p1))
				printf("Decryption of delegation ciphertext fails, please check the algorithm or codes!\n");
			else
				{
					time2=get_time();
					td2[i]=time2-time1;
//					printf("the time of decrypting delegation ciphertext (without verification) is %f second.\n",td2[i]);
//					printf("Decryption of re-encrypted ciphertext successess!\n");
//					element_printf("The decrypting plaintext p1 = %B.\n",p1);
				}	
		}
//		printf("the time of ciphertext verification before decrypting delegated ciphertext is %f s\n\n",time3-time1);
	
	//user I change identity to nI, and generate new private key sk_nI
//	printf("----------Key Generation for new identity nI---------\n");
	element_random(nI);    //identity of user i
	time1=get_time();
	element_random(nti);
	element_random(nxi);
	element_random(nyi);
	element_random(nzi);
	element_mul(ntempi,b,nI);       //ntempi,no tempi
	element_add(ntempi,a,ntempi);   //ntempi=a+b*nI
	element_add(nAi1,c,nti);
	element_div(nAi1,nAi1,ntempi);  //nAi1=(c+t)/(a+b*nI)
	element_pow_zn(nAi2,h,nti);
	element_pow_zn(nAi3,g,nti);
	element_add(nBi1,a,nxi);
	element_div(nBi1,nBi1,ntempi);
	element_add(nBi2,b,nyi);
	element_div(nBi2,nBi2,ntempi);
	element_div(nBi3,nzi,ntempi);
	element_pow_zn(nDi1,h,nxi);
	element_pow_zn(nDi2,h,nyi);
	element_pow_zn(nDi3,h,nzi);
	time2=get_time();
	tkg3[i]=time2-time1;
//	printf("the time of computing private key for new identity nI is %f second.\n",tkg3[i]);
//	byte_p=element_length_in_bytes(nAi1)+element_length_in_bytes(nAi2)+element_length_in_bytes(nAi3);
//	byte_p=byte_p+element_length_in_bytes(nBi1)+element_length_in_bytes(nBi2)+element_length_in_bytes(nBi3);
//	byte_p=byte_p+element_length_in_bytes(nDi1)+element_length_in_bytes(nDi2)+element_length_in_bytes(nDi3);
//	printf("The private key of user i is sk_nI = (nAi1,nAi2,nAi3,nBi1,nBi2,nBi3,nDi1,nDi2,nDi3).\n");
//	printf("The length of the private key of user i is %d.\n",byte_p);

	//generation of update re-encryption key from identity I to nI
//	printf("-----------Update Re-encryption Key Generation--------\n");
	time1=get_time();
	element_random(uk1);
	element_random(uk2);
	element_mul(temp_urk1,uk2,Bi3);      //uk2*Bi3
	element_add(temp_urk1,temp_urk1,Bi2);  //Bi2+uk2*Bi3
	element_mul(temp_urk1,temp_urk1,nI);   //(Bi2+uk2*Bi3)*nI
	element_mul(urk1,uk1,Bi3);             //uk1*Bi3
	element_add(urk1,urk1,Bi1);            //Bi1+uk1*Bi3
	element_add(urk1,urk1,temp_urk1);      //(Bi1+uk1*Bi3)+((Bi2+uk2*Bi3)*nI)
	element_pow_zn(temp_urk2,Di3,uk2);     //Di3^uk2
	element_mul(temp_urk2,Di2,temp_urk2);  //Di2*Di3^uk2
	element_pow_zn(temp_urk2,temp_urk2,nI); //(Di2*Di3^uk2)^nI
	element_pow_zn(urk2,Di3,uk1);           //D31^uk1
	element_mul(urk2,Di1,urk2);             //Di1*D31^uk1
	element_mul(urk2,urk2,temp_urk2);       //urk2=(Di1*D31^uk1)*((Di2*Di3^uk2)^nI)
	time2=get_time();
	trkg2[i]=time2-time1;
//	printf("the time of computing update re-encryption key is %f second.\n",trkg2[i]);
//	byte_p=element_length_in_bytes(urk1)+element_length_in_bytes(urk2);
//	printf("The update re-encryption key from identity I to new identity nI is urk = (urk1,urk2).\n");

	//re-encrypt for updating ciphertext
//	printf("-------------update re-encryption-------------\n");
	time1=get_time();
	pairing_apply(temp1,svk,haxi_Ci,pairing);    //e(svk,hash(Ci))=e(g^ssk,hash(Ci))
	pairing_apply(temp2,Ci6,g,pairing);            //e(g,Ci6)=e(g,hash(Ci)^ssk)
	if(!element_cmp(temp1,temp2))
		check=1;
	element_pow_zn(temp_urk2,h1,w);
	element_mul(temp_urk2,temp_urk2,h2);          //h1^w*h2
	pairing_apply(temp1,Ci1,temp_urk2,pairing);   //e(g^r,h1^w*h2)
	pairing_apply(temp2,g,Ci4,pairing);           //e(g,(h1^w*h2)^r)
	if(!element_cmp(temp1,temp2))
		check+=1;
	element_pow_zn(temp_urk2,h3,haxi_svk);
	element_mul(temp_urk2,temp_urk2,h4);
	pairing_apply(temp1,Ci1,temp_urk2,pairing);
	pairing_apply(temp2,g,Ci5,pairing);
	if(!element_cmp(temp1,temp2))
		check+=1;
	time3=get_time();
	if(check<3)
		printf("Verification fails, please check the codes!\n");
	else
		{
//			printf("Verification of ciphertext to be updated is successful!\n");
			element_set(nCi0,Ci0);
			element_set(nCi1,Ci1);
			element_set(nCi2,Ci2);
			pairing_apply(temp2,Ci1,urk2,pairing);   //e(g^r,urk2)
			element_pow_zn(nCi3,Ci3,urk1);
			element_div(nCi3,nCi3,temp2);
			element_set(nCi4,Ci4);
			element_set(nCi5,Ci5);
			element_set(nCi6,Ci6);
			time2=get_time();
			tre2[i]=time2-time1;
//			printf("the time of updating ciphertext (without verification) is %f second.\n",tre2[i]);
		}
//	printf("the time of ciphertext verification before updating ciphertext is %f s\n\n",time3-time1);

	//decryption of updated ciphertext C_I2 
//	printf("-----------Decrypt updated ciphertext nC_I2 with new key sk_nI--------\n");
	time1=get_time();
	pairing_apply(temp1,svk,haxi_Ci,pairing);    //e(svk,hash(Ci))=e(g^ssk,hash(Ci))
	pairing_apply(temp2,nCi6,g,pairing);            //e(g,nCi6)=e(g,hash(Ci)^ssk)
	if(!element_cmp(temp1,temp2))
		check=1;
	element_pow_zn(temp_drk2,h1,w);
	element_mul(temp_drk2,temp_drk2,h2);          //h1^w*h2
	pairing_apply(temp1,nCi1,temp_drk2,pairing);   //e(g^r,h1^w*h2)
	pairing_apply(temp2,g,nCi4,pairing);           //e(g,(h1^w*h2)^r)
	if(!element_cmp(temp1,temp2))
		check+=1;
	element_pow_zn(temp_drk2,h3,haxi_svk);
	element_mul(temp_drk2,temp_drk2,h4);
	pairing_apply(temp1,nCi1,temp_drk2,pairing);  //e(g^r,(h3^(svk)*h4))
	pairing_apply(temp2,g,nCi5,pairing);
	if(!element_cmp(temp1,temp2))
		check+=1;
	time3=get_time();
	if(check<3)
		printf("Verification fails, please check the codes!\n");
	else
		{
//			printf("The updated ciphertext is well-formed.\n");
			pairing_apply(temp1,nCi1,nAi2,pairing);  //e(nCi1,nAi2)=e(g^r2,h^nti)
			element_mul(p1,nCi2,temp1);              //nCi2*e(nCi1,nAi2)=(m2*e(g,h)^(c*r2))*e(g^r2,h^nti)=m2*e(g,h)^(r2*(c+nti))
			element_pow_zn(temp2,nCi3,nAi1);         //nCi3^nAi1=(e(g,h)^(a+b*nI)*r2)^((c+nti)/(a+b*nI))
			element_div(p1,p1,temp2);
			if(element_cmp(m1,p1))
				printf("Decryption of updated ciphertext fails, please check the algorithm or codes!\n");
			else
				{
					time2=get_time();
					td3[i]=time2-time1;
//					printf("the time of decrypting updated ciphertext (without verification) is %f second.\n",td3[i]);
//					printf("Decryption of updated ciphertext successess!\n");
//					element_printf("The decrypting plaintext p1= %B.\n",p1);
				}	
		}	
//	printf("the time of ciphertext verification before decrypting updated ciphertext is %f s\n\n",time3-time1);
	
	T_s+=ts[i];
	T_kg1+=tkg1[i];
	T_kg2+=tkg2[i];
	T_e+=te[i];
	T_d1+=td1[i];
	T_rkg1+=trkg1[i];
	T_re1+=tre1[i];
	T_d2+=td2[i];
	T_kg3+=tkg3[i];
	T_rkg2+=trkg2[i];
	T_re2+=tre2[i];
	T_d3+=td3[i];
	}
	printf(">>>the time of setup is: %f ms\n",1000*T_s/CHISHU);
	printf(">>>the time of key generation for I is: %f ms\n",1000*T_kg1/CHISHU);
	printf(">>>the time of encryption (original ciphertext) is: %f ms\n",1000*T_e/CHISHU);
	printf(">>>the time of decryption for data owner is: %f ms\n",1000*T_d1/CHISHU);
	printf(">>>the time of key generation for J is: %f ms\n",1000*T_kg2/CHISHU);
	printf(">>>the time of re-encryption key generation for delegation is: %f ms\n",1000*T_rkg1/CHISHU);
	printf(">>>the time of re-encrypt for delegation is: %f ms\n",1000*T_re1/CHISHU);
	printf(">>>the time of decryption for requester is: %f ms\n",1000*T_d2/CHISHU);
	printf(">>>the time of key generation for new identity nI is: %f ms\n",1000*T_kg3/CHISHU);
	printf(">>>the time of re-encryption key generation for update is: %f ms\n",1000*T_rkg2/CHISHU);
	printf(">>>the time of re-encrypt for update is: %f ms\n",1000*T_re2/CHISHU);
	printf(">>>the time of decryption for updated ciphertext is: %f ms\n",1000*T_d3/CHISHU);

	//release RAM
	element_clear(g);
	element_clear(h);
	element_clear(h1);
	element_clear(h2);
	element_clear(h3);
	element_clear(h4);
	element_clear(pair_a);
	element_clear(pair_b);
	element_clear(par_c);
	element_clear(a);
	element_clear(b);
	element_clear(c);
	element_clear(Ai1);
	element_clear(Ai2);
	element_clear(Ai3);
	element_clear(Bi1);
	element_clear(Bi2);
	element_clear(Bi3);
	element_clear(Di1);
	element_clear(Di2);
	element_clear(Di3);
	element_clear(I);
	element_clear(ti);
	element_clear(xi);
	element_clear(yi);
	element_clear(zi);
	element_clear(tempi);
	element_clear(Aj1);
	element_clear(Aj2);
	element_clear(Aj3);
	element_clear(Bj1);
	element_clear(Bj2);
	element_clear(Bj3);
	element_clear(Dj1);
	element_clear(Dj2);
	element_clear(Dj3);
	element_clear(J);
	element_clear(tj);
	element_clear(xj);
	element_clear(yj);
	element_clear(zj);
	element_clear(tempj);
	element_clear(w);
	element_clear(dk1);
	element_clear(dk2);
	element_clear(dk3);
	element_clear(drk1);
	element_clear(drk2);
	element_clear(drk3);
	element_clear(temp_drk1);
	element_clear(temp_drk2);
	element_clear(m1);
	element_clear(x);
	element_clear(ssk);
	element_clear(svk);
	element_clear(haxi_svk);
	element_clear(Ci0);
	element_clear(Ci1);
	element_clear(Ci2);
	element_clear(Ci3);
	element_clear(Ci4);
	element_clear(Ci5);
	element_clear(Ci6);
	element_clear(haxi_Ci);    
	element_clear(r);
	element_clear(temp1);
	element_clear(temp2);
	element_clear(p1);
	element_clear(Cj0);
	element_clear(Cj1);
	element_clear(Cj2);
	element_clear(Cj3);
	element_clear(Cj4);
	element_clear(Cj5);
	element_clear(Cj6);
	element_clear(nAi1);
	element_clear(nAi2);
	element_clear(nAi3);
	element_clear(nBi1);
	element_clear(nBi2);
	element_clear(nBi3);
	element_clear(nDi1);
	element_clear(nDi2);
	element_clear(nDi3);
	element_clear(nI);
	element_clear(nti);
	element_clear(nxi);
	element_clear(nyi);
	element_clear(nzi);
	element_clear(ntempi);
	element_clear(uk1);
	element_clear(uk2);
	element_clear(urk1);
	element_clear(urk2);
	element_clear(temp_urk1);
	element_clear(temp_urk2);
	element_clear(nCi0);
	element_clear(nCi1);
	element_clear(nCi2);
	element_clear(nCi3);
	element_clear(nCi4);
	element_clear(nCi5);
	element_clear(nCi6);

	pairing_clear(pairing);
	return 0;

}