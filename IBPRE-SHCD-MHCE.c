//IBPRE-SHCD-MHCE for dissertation
//For ciphertext update, Liang et al. 2014, multi-hop,I=(IDi||t)-->I1=(IDi||t1)-->I2=(IDi||t2)
//For ciphertext delegation, Liange et al. 2012, single-hop,I(I1 or I2)-->J

#include<pbc.h>
#include<pbc_time.h>
#define CHISHU 1

int main()
{
//variants declear
	pairing_t pairing; //pairing declear,e:G1*G1->GT
	element_t g,g1,g2,g3,u,v,h1,h2,h3,x,msk;    //system parameters declear
	element_t I,r,skI_1,skI_2,skI_3,skI_4;  //private key for identity I=(IDi||t)
//	element_t skIw_1,skIw_2,skIw_3,rw,rI;   //rI=r+rw
	element_t G1temp1;   //for storing temporary variants of group G1
	element_t w,cida,s,CI0,CI1,CI2,CI4,haxi_CI0,CI5,CI6,haxi_CI,ssk,svk;    //for encrypting message without CI3 
	element_t G1temp2,GTtemp1,GTtemp2,p;  //for decryption of original, use p to check m (here is cida)
	element_t J,rJ,skJ_1,skJ_2,skJ_3,skJ_4;  //private key for identity J
	element_t Ro,t,CIDA,pdrk1,pdrk2,pdrk3,pdrk4,drk0,drk1,drk2,drk3,drk4,haxi_drk0,haxi_drk,haxi_CIDA,ssk_drk,svk_drk;   //for generating delegation key
	element_t CJ0,CJ1,CJ2,CJ4,CJ5,CJ6,haxi_CJ0,haxi_CJ,p2;    //for delegation ciphertext
	element_t I1,r1,skI1_1,skI1_2,skI1_3,skI1_4;          //private key for identity I1=(IDi||t1)
//	element_t skI1w_1,skI1w_2,skI1w_3;  
	element_t purk1,purk2,purk3,purk4,purk5,deta,urk1,urk2,urk3,urk4,urk5;  //for update re-encryption key
	element_t CI1_0,CI1_1,CI1_2,CI1_4,CI1_5,CI1_6,haxi_CI1_0,haxi_CI1;
	
	
	int check=0;
	double time1,time2;
	double ts[CHISHU],tkgI[CHISHU],tkgI1[CHISHU],te[CHISHU],tod[CHISHU],tdd[CHISHU],tdrkg[CHISHU],turkg[CHISHU],tdre[CHISHU],ture[CHISHU],td3[CHISHU];
	double T_s,T_kgI,T_kgI1,T_e,T_od,T_dd,T_drkg,T_urkg,T_dre,T_ure,T_d3;
	int i;T_s=0;T_kgI=0;T_kgI1=0;T_e=0;T_od=0;T_dd=0;T_drkg=0;T_urkg=0;T_dre=0;T_ure=0,T_d3=0;

//variants init
	a_param_input(pairing); //input type-A parameters
	element_init_G1(g,pairing);  
	element_init_G1(g1,pairing);
	element_init_G1(g2,pairing);
	element_init_G1(g3,pairing);
	element_init_G1(h1,pairing);
	element_init_G1(h2,pairing);
	element_init_G1(h3,pairing);
	element_init_G1(u,pairing);
	element_init_G1(v,pairing);
	element_init_Zr(x,pairing);
	element_init_G1(msk,pairing);   //mpp and msk
	element_init_Zr(I,pairing);     //I=IDi||expiration date
	element_init_Zr(r,pairing);
	element_init_G1(skI_1,pairing);
	element_init_G1(skI_2,pairing);
	element_init_G1(skI_3,pairing);
	element_init_G1(skI_4,pairing);
	element_init_Zr(w,pairing);
//	element_init_Zr(rw,pairing);
//	element_init_Zr(rI,pairing);
//	element_init_G1(skIw_1,pairing);
//	element_init_G1(skIw_2,pairing);
//	element_init_G1(skIw_3,pairing);
	element_init_G1(G1temp1,pairing);
	element_init_GT(cida,pairing);   //for encryption
	element_init_Zr(s,pairing);
	element_init_Zr(ssk,pairing);
	element_init_G1(svk,pairing);
	element_init_G1(CI0,pairing);
	element_init_G1(CI1,pairing);
	element_init_GT(CI2,pairing);
	element_init_G1(haxi_CI,pairing);
	element_init_G1(CI4,pairing);     //u^w*v, for condition
	element_init_Zr(haxi_CI0,pairing);
	element_init_G1(haxi_CI,pairing);
	element_init_G1(CI5,pairing);     
	element_init_G1(CI6,pairing);
	element_init_GT(p,pairing);
	element_init_G1(G1temp2,pairing);
	element_init_GT(GTtemp1,pairing);
	element_init_GT(GTtemp2,pairing);
	element_init_Zr(J,pairing);     //J=IDJ||expiration date
	element_init_Zr(rJ,pairing);
	element_init_G1(skJ_1,pairing);
	element_init_G1(skJ_2,pairing);
	element_init_G1(skJ_3,pairing);	
	element_init_G1(skJ_4,pairing);	
	element_init_Zr(Ro,pairing);             //for delegation token
	element_init_Zr(t,pairing);
	element_init_GT(CIDA,pairing);          //CIDA
	element_init_G1(pdrk1,pairing);
	element_init_G1(haxi_CIDA,pairing);     //H(CIDA)
	element_init_G1(pdrk2,pairing);
	element_init_G1(pdrk3,pairing);
	element_init_G1(pdrk4,pairing);
	element_init_G1(drk0,pairing);
	element_init_G1(drk1,pairing);
	element_init_GT(drk2,pairing);
	element_init_G1(drk3,pairing);
	element_init_Zr(haxi_drk0,pairing);
	element_init_G1(haxi_drk,pairing);
	element_init_G1(drk4,pairing);
	element_init_Zr(ssk_drk,pairing);
	element_init_G1(svk_drk,pairing);
	element_init_G1(CJ0,pairing);         //for delegation ciphertext
	element_init_G1(CJ1,pairing);
	element_init_GT(CJ2,pairing);
	element_init_G1(CJ4,pairing); 
	element_init_G1(CJ5,pairing);     
	element_init_G1(CJ6,pairing);
	element_init_Zr(haxi_CJ0,pairing);
	element_init_G1(haxi_CJ,pairing);
	element_init_GT(p2,pairing);
	element_init_Zr(I1,pairing);
	element_init_Zr(r1,pairing);
	element_init_G1(skI1_1,pairing);
	element_init_G1(skI1_2,pairing);
	element_init_G1(skI1_3,pairing);
	element_init_G1(skI1_4,pairing);
//	element_init_G1(skI1w_1,pairing);
//	element_init_G1(skI1w_2,pairing);
//	element_init_G1(skI1w_3,pairing);
	//for update re-encryption key
	element_init_Zr(deta,pairing);
	element_init_G1(purk1,pairing);
	element_init_G1(purk2,pairing);
	element_init_G1(purk3,pairing);
	element_init_G1(purk4,pairing);
	element_init_G1(purk5,pairing);
	element_init_G1(urk1,pairing);
	element_init_G1(urk2,pairing);
	element_init_G1(urk3,pairing);
	element_init_G1(urk4,pairing);
	element_init_G1(urk5,pairing);
	//for updated ciphertext to I1
	element_init_G1(CI1_0,pairing);
	element_init_G1(CI1_1,pairing);
	element_init_GT(CI1_2,pairing);
	element_init_G1(CI1_4,pairing);
	element_init_G1(CI1_5,pairing);
	element_init_G1(CI1_6,pairing);
	element_init_Zr(haxi_CI1_0,pairing);
	element_init_G1(haxi_CI1,pairing);


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
	element_random(g);
	element_random(x);     //x=alpha
	element_pow_zn(g1,g,x);
	element_random(g2);
	element_random(g3);
	element_pow_zn(msk,g2,x);
	element_random(u);
	element_random(v);
	element_random(h1);
	element_random(h2);
	element_random(h3);
	time2=get_time();
	ts[i]=time2-time1;
//	element_printf(">>>the generator of the G1 is g= %B\n",g);
//	printf(">>>the time of setup is: %fs\n\n",time2-time1);

	//generation of key pair for user i
//	printf("----------Key Generation--------\n");
	element_random(I);
	element_random(w);
	time1=get_time();
	element_random(r);
	element_pow_zn(skI_1,h1,I);
	element_mul(skI_1,skI_1,g3);
	element_pow_zn(skI_1,skI_1,r);
	element_mul(skI_1,msk,skI_1);
	element_pow_zn(skI_2,g,r);
	element_pow_zn(skI_3,h2,r);
	element_pow_zn(skI_4,h3,r);
	time2=get_time();
	tkgI[i]=time2-time1;
//	printf("the time of generating private key skI is %f s.\n\n",time2-time1);

	//generation of key pair for user J
	//	printf("----------Key Generation for J---------\n");
	element_random(J);
	element_random(rJ);
	element_pow_zn(G1temp1,h1,J);    //h1^J
	element_mul(skJ_1,G1temp1,g3);  //h1^J*g3
	element_pow_zn(G1temp1,h2,w);    //h2^w
	element_mul(skJ_1,skJ_1,G1temp1);  //h1^J*h2^w*g3
	element_pow_zn(skJ_1,skJ_1,rJ);    //(h1^J*h2^w*g3)^rJ
	element_pow_zn(skJ_2,g,rJ);
	element_pow_zn(skJ_3,h2,rJ);
	element_pow_zn(skJ_4,h3,rJ);

	//original ciphertext of m
//	printf("---------Encryption m under identity I-----------\n");
	element_random(haxi_CI0);
	time1=get_time();
	element_random(ssk);
	element_pow_zn(svk,g,ssk);  
	element_set(CI0,svk);              //CI0=svk   
	element_random(s);          
	element_pow_zn(CI1,g,s);           //CI1=g^s
	pairing_apply(CI2,g1,g2,pairing);  
	element_pow_zn(CI2,CI2,s);
	element_random(cida);              //CI2=cida*e(g1,g2)^s
	element_mul(CI2,cida,CI2);
	element_pow_zn(CI4,u,w);          
	element_mul(CI4,CI4,v);          
	element_pow_zn(CI4,CI4,s);        //(u^w*v)^s
	element_pow_zn(G1temp1,h1,I);     //h1^I
	element_mul(CI5,G1temp1,g3);      //h1^I*g3
	element_pow_zn(G1temp1,h2,w);     //h2^w
	element_mul(CI5,CI5,G1temp1);     //h1^I*h2^w*g3
	element_pow_zn(G1temp1,h3,haxi_CI0);   //h3^haxi_CI0=h3^svk, use haxi_CI0 (Zr) to replace svk (G1)
	element_mul(CI5,CI5,G1temp1);     //h1^I*h2^w*h3^svk*g3
	element_pow_zn(CI5,CI5,s);        //(h1^I*h2^w*h3^svk*g3)^s
	element_random(haxi_CI);          //use randomness as hash(w,CI1,CI3,CI4,CI5), without CI3
	element_pow_zn(CI6,haxi_CI,ssk);  //S(ssk,(w,CI1,CI3,CI4,CI5))
	time2=get_time();
	te[i]=time2-time1;
//	element_printf("The cida = %B\n",cida);
//	byte_p=element_length_in_bytes(w)+element_length_in_bytes(CI0)+element_length_in_bytes(CI1)+element_length_in_bytes(CI2);
//	byte_p+=element_length_in_bytes(CI4)+element_length_in_bytes(CI5)+element_length_in_bytes(CI6);
//	printf("The length of the original ciphtertext (without CI3) is %d.\n\n",byte_p);
//	printf("the time (exclude PRF) of encrypting m to be a original ciphertext is %fs.\n\n",time2-time1);


//decryption of original ciphertext m
//	printf("--------------Decrypting for m here is cida---------\n");
	time1=get_time();
	//verify the ciphertext
	//verify the condition
	element_pow_zn(G1temp1,u,w);
	element_mul(G1temp1,G1temp1,v);               //u^w*v
	pairing_apply(GTtemp1,G1temp1,CI1,pairing);   //e(g^s,u^w*v)
	pairing_apply(GTtemp2,g,CI4,pairing);         //e(g,(u^w*v)^s)
	if(!element_cmp(GTtemp1,GTtemp2))
		check=1;
	//veriry the I,w,svk
	element_pow_zn(G1temp1,h1,I);
	element_pow_zn(G1temp2,h2,w);
	element_mul(G1temp1,G1temp1,G1temp2);
	element_pow_zn(G1temp2,h3,haxi_CI0);
	element_mul(G1temp1,G1temp1,G1temp2);
	element_mul(G1temp1,G1temp1,g3);         //h1^I*h2^w*h3^CI0*g3
	pairing_apply(GTtemp1,g,CI5,pairing);    //e(g,CI5)
	pairing_apply(GTtemp2,CI1,G1temp1,pairing);  //e(g^s,h1^I*h2^w*h3^CI0*g3)
	if(!element_cmp(GTtemp1,GTtemp2))
		check+=1;
	//veriry signature
	pairing_apply(GTtemp1,g,CI6,pairing);
	pairing_apply(GTtemp2,CI0,haxi_CI,pairing);
	if(!element_cmp(GTtemp1,GTtemp2))
		check+=1;
	if(check<3)
		printf("The original ciphertext is invalid, aborts!\n");
	else
		{
//			printf("The verification of original ciphertext successes.\n");
			pairing_apply(GTtemp1,skI_2,CI5,pairing);
			element_pow_zn(G1temp1,skI_4,haxi_CI0);
			element_mul(G1temp1,skI_1,G1temp1);
			element_pow_zn(G1temp2,skI_3,w);     
			element_mul(G1temp1,G1temp1,G1temp2);
			pairing_apply(GTtemp2,G1temp1,CI1,pairing);
			element_div(p,GTtemp1,GTtemp2);
			element_mul(p,CI2,p);
			if(element_cmp(cida,p))
				printf("The decryption of original ciphertext fails, please check the codes.\n");
			else
				{
//					printf("Decryption successes.\n");
					time2=get_time();
					tod[i]=time2-time1;
//					element_printf("The plaintext after decrypting original ciphertext is p = %B\n",p);
//					printf("the time of decrypting original ciphertext CI is %f s\n\n",time2-time1);	
				}
		}

	//generation of deleation re-encryption key 
//	printf("------------delegation re-encryption key from I to J----------\n");
	element_random(haxi_CIDA);
	element_random(haxi_drk0);
	element_random(haxi_drk);
	time1=get_time();
	element_random(Ro);
	element_random(t);
	element_random(CIDA);
	element_pow_zn(pdrk1,h2,w);   
	element_mul(pdrk1,pdrk1,g3);         //h2^w*g3
	element_pow_zn(pdrk1,pdrk1,Ro);      //(h2^w*g3)^Ro
	element_mul(pdrk1,skI_1,pdrk1);     //g2^x*(h1^I*g3)^r*(h2^w*g3)^Ro
	element_pow_zn(G1temp1,skI_3,w);    //(h2^r)^w
	element_mul(pdrk1,pdrk1,G1temp1);   //g2^x*(h1^I*g3)^r*(h2^r)^w*(h2^w*g3)^Ro
	element_pow_zn(pdrk2,g,Ro);          //g^Ro
	element_mul(pdrk2,skI_2,pdrk2);     //g^r*g^Ro
	element_mul(pdrk2,pdrk2,haxi_CIDA);  //g^(r+Ro)*haxi_CIDA
	element_pow_zn(pdrk3,h3,Ro);         //h3^Ro
	element_mul(pdrk3,skI_4,pdrk3);     //h3^r*h3^Ro
	element_pow_zn(pdrk4,h1,Ro);         //h1^Ro
	element_random(ssk_drk);             //ssk'
	element_pow_zn(svk_drk,g,ssk_drk);   //svk'=g^ssk'
	element_set(drk0,svk_drk);           //drk0=svk'
	element_pow_zn(drk1,g,t);            //drk1=g^t
	pairing_apply(drk2,g1,g2,pairing);   //e(g1,g2)
	element_pow_zn(drk2,drk2,t);         //e(g1,g2)^t
	element_mul(drk2,CIDA,drk2);         //drk2=CIDA*e(g1,g2)^t
	element_pow_zn(G1temp1,h1,J);        //h1^J  
	element_mul(drk3,G1temp1,g3);        //h1^J*g3
	element_pow_zn(G1temp1,h2,w);        //h2^w
	element_mul(drk3,drk3,G1temp1);      //h1^J*h2^w*g3
	element_pow_zn(G1temp1,h3,haxi_drk0);  //h3^svk'
	element_mul(drk3,drk3,G1temp1);        //h1^J*h2^w*h3^svk'
	element_pow_zn(drk3,drk3,t);           //drk3=(h1^J*h2^w*h3^svk'*g3)^t
	element_pow_zn(drk4,haxi_drk,ssk_drk);  //drk4=S(ssk',(drk1,drk2,drk3))
	time2=get_time();
	tdrkg[i]=time2-time1;
//	element_printf("The CIDA = %B\n",CIDA);
//	byte_p=element_length_in_bytes(pdrk1)+element_length_in_bytes(pdrk2)+element_length_in_bytes(pdrk3)+element_length_in_bytes(pdrk4);
//	byte_p+=element_length_in_bytes(drk0)+element_length_in_bytes(drk1)+element_length_in_bytes(drk2)+element_length_in_bytes(drk3)+element_length_in_bytes(drk4);
//	printf("The length of the delegation re-encryption key is %d.\n",byte_p);
//	printf("the time of generating delegation re-encryption key drk_I-J is %f s\n\n",time2-time1);

	//generation of delegation ciphertext
//	printf("--------generation of delegation ciphertext---------\n");
	time1=get_time();
	//verify the ciphertext
	//verify the condition
	element_pow_zn(G1temp1,u,w);
	element_mul(G1temp1,G1temp1,v);               //u^w*v
	pairing_apply(GTtemp1,G1temp1,CI1,pairing);   //e(g^s,u^w*v)
	pairing_apply(GTtemp2,g,CI4,pairing);         //e(g,(u^w*v)^s)
	if(!element_cmp(GTtemp1,GTtemp2))
		check=1;
	//veriry the I,w,svk
	element_pow_zn(G1temp1,h1,I);
	element_pow_zn(G1temp2,h2,w);
	element_mul(G1temp1,G1temp1,G1temp2);
	element_pow_zn(G1temp2,h3,haxi_CI0);
	element_mul(G1temp1,G1temp1,G1temp2);
	element_mul(G1temp1,G1temp1,g3);         //h1^I*h2^w*h3^CI0*g3
	pairing_apply(GTtemp1,g,CI5,pairing);    //e(g,CI5)
	pairing_apply(GTtemp2,CI1,G1temp1,pairing);  //e(g^s,h1^I*h2^w*h3^CI0*g3)
	if(!element_cmp(GTtemp1,GTtemp2))
		check+=1;
	//veriry signature
	pairing_apply(GTtemp1,g,CI6,pairing);
	pairing_apply(GTtemp2,CI0,haxi_CI,pairing);
	if(!element_cmp(GTtemp1,GTtemp2))
		check+=1;
	if(check<3)
		printf("The original ciphertext is invalid, aborts!\n");
	else
		{
//			printf("The verification of original ciphertext and delegation key successes.\n");
			pairing_apply(GTtemp1,pdrk2,CI5,pairing);   //e(pdrk2,CI5)
			element_pow_zn(G1temp1,pdrk3,haxi_CI0);    //pdrk3^svk'   这个地方出错了，应该是pdrk3^svk
			element_mul(G1temp1,pdrk1,G1temp1);         //pdrk1*pdrk3^svk
			element_pow_zn(G1temp2,pdrk4,I);            //pdrk4^I
			element_mul(G1temp1,G1temp1,G1temp2);       //pdrk1*pdrk3^svk*pdrk4^I
			pairing_apply(GTtemp2,G1temp1,CI1,pairing); //e(pdrk1*pdrk3^svk*pdrk4^I,CI1)
			element_div(CJ2,GTtemp1,GTtemp2);           //e(pdrk2,CI5)/e(pdrk1*pdrk3^svk*pdrk4^I,CI1)
			element_mul(CJ2,CI2,CJ2);                   //CJ2=CI2*e(pdrk2,CI5)/e(pdrk1*pdrk3^svk*pdrk4^I,CI1)
			element_set(CJ0,CI0);
			element_set(CJ1,CI1);
			element_set(CJ4,CI4);
			element_set(CJ5,CI5);
			element_set(CJ6,CI6);
			element_set(haxi_CJ0,haxi_CI0);
			element_set(haxi_CJ,haxi_CI);
			time2=get_time();
			tdre[i]=time2-time1;
//			byte_p=element_length_in_bytes(CJ0)+element_length_in_bytes(CJ1)+element_length_in_bytes(CJ2)+element_length_in_bytes(CJ4)+element_length_in_bytes(CJ5)+element_length_in_bytes(CJ6);
//			byte_p+=element_length_in_bytes(drk0)+element_length_in_bytes(drk1)+element_length_in_bytes(drk2)+element_length_in_bytes(drk3)+element_length_in_bytes(drk4);
//			printf("The length of the delegation re-encryption key is %d.\n",byte_p);
//			printf("the time of generating delegation ciphertext CJ is %f s\n\n",time2-time1);
		}

	//decryption of delegation ciphertext
//	printf("--------decryption of delegation ciphertext---------\n");
	time1=get_time();
	//verify the ciphertext
	//verify the condition
	element_pow_zn(G1temp1,u,w);
	element_mul(G1temp1,G1temp1,v);               //u^w*v
	pairing_apply(GTtemp1,G1temp1,CJ1,pairing);   //e(g^s,u^w*v)
	pairing_apply(GTtemp2,g,CJ4,pairing);         //e(g,(u^w*v)^s)
	if(!element_cmp(GTtemp1,GTtemp2))
		check=1;
	//veriry the I,w,svk
	element_pow_zn(G1temp1,h1,I);
	element_pow_zn(G1temp2,h2,w);
	element_mul(G1temp1,G1temp1,G1temp2);
	element_pow_zn(G1temp2,h3,haxi_CJ0);
	element_mul(G1temp1,G1temp1,G1temp2);
	element_mul(G1temp1,G1temp1,g3);         //h1^I*h2^w*h3^CI0*g3
	pairing_apply(GTtemp1,g,CJ5,pairing);    //e(g,CI5)
	pairing_apply(GTtemp2,CJ1,G1temp1,pairing);  //e(g^s,h1^I*h2^w*h3^CI0*g3)
	if(!element_cmp(GTtemp1,GTtemp2))
		check+=1;
	//veriry signature
	pairing_apply(GTtemp1,g,CJ6,pairing);
	pairing_apply(GTtemp2,CJ0,haxi_CJ,pairing);
	if(!element_cmp(GTtemp1,GTtemp2))
		check+=1;
	//verify the delegation key
	element_pow_zn(G1temp1,h1,J);
	element_pow_zn(G1temp2,h2,w);
	element_mul(G1temp1,G1temp1,G1temp2);
	element_pow_zn(G1temp2,h3,haxi_drk0);
	element_mul(G1temp1,G1temp1,G1temp2);
	element_mul(G1temp1,G1temp1,g3);         //h1^J*h2^w*h3^drk0*g3
	pairing_apply(GTtemp1,g,drk3,pairing);    //e(g,drk3)
	pairing_apply(GTtemp2,drk1,G1temp1,pairing);  //e(g^t,h1^J*h2^w*h3^drk0*g3)
	if(!element_cmp(GTtemp1,GTtemp2))
		check+=1;
	//verify the signature of the drk
	pairing_apply(GTtemp1,g,drk4,pairing);
	pairing_apply(GTtemp2,drk0,haxi_drk,pairing);
	if(!element_cmp(GTtemp1,GTtemp2))
		check+=1;
	if(check<5)
		printf("The delegation ciphertext is invalid, aborts!\n");
	else
		{
//			printf("The verification of delegation successes.\n");
			pairing_apply(GTtemp1,skJ_2,drk3,pairing);            //e(skJ_2,drk3)=e(g^rJ,(h1^J*h2^w*h3^svk'*g3)^t)
			element_pow_zn(G1temp1,skJ_4,haxi_drk0);              //(h3^rJ)^svk'          
			element_mul(G1temp1,skJ_1,G1temp1);                   //msk*(h1^J*g3)^rJ*(h3^rJ)^svk'  
			element_pow_zn(G1temp2,skJ_3,w);                      //(h2^rJ)^w
			element_mul(G1temp1,G1temp1,G1temp2);                 //msk*(h1^J*g3)^rJ*(h3^rJ)^svk'*(h2^rJ)^w  
			pairing_apply(GTtemp2,G1temp1,drk1,pairing);
			element_div(p2,GTtemp1,GTtemp2);
			element_mul(p2,drk2,p2);
			if(!element_cmp(p2,CIDA))
				printf("The decryption for CIDA with decryption key skJw fails, aborts!\n");
			else
				{
//					printf("Getting CIDA success!\n");
					pairing_apply(GTtemp1,haxi_CIDA,CJ5,pairing);
					element_div(p,CJ2,GTtemp1);
					if(element_cmp(p,cida))
						printf("decryption of cida fails, abort!\n");
					else
						{
							time2=get_time();
							tdd[i]=time2-time1;
//							element_printf("The cida = %B\n",p);
//							printf("the time of decrypting delegation ciphertext is %f s\n\n",time2-time1);
						}
				}
		}

	//generation of key pair for identity I1
//	printf("----------Key Generation for identity I1---------\n");
	element_random(I1);
	time1=get_time();
	element_random(r1);
	element_pow_zn(skI1_1,h1,I1);
	element_mul(skI1_1,skI1_1,g3);
	element_pow_zn(skI1_1,skI1_1,r1);    //(h1^I1*g3)^r1
	element_mul(skI1_1,msk,skI1_1);
	element_pow_zn(skI1_2,g,r1);
	element_pow_zn(skI1_3,h2,r1);
	element_pow_zn(skI1_4,h3,r1);     //for private key
	time2=get_time();
	tkgI1[i]=time2-time1;	
//	printf("the time of generating private key skI1 is %f s.\n\n",time2-time1);

	//generation of update re-encryption key from I=(IDi||t) to I1=(IDi||t1)
//	printf("----------generation of update re-encryption key I to I1---------\n");
	time1=get_time();
	element_random(deta);
	element_pow_zn(purk1,g3,deta);   //g3^deta
	element_div(purk1,purk1,skI1_1); //g3^deta/skI1_1
	element_pow_zn(purk2,g,deta);    //g^deta
	element_div(purk2,purk2,skI1_2); //g^deta/skI1_2
	element_pow_zn(purk3,h3,deta);   //h3^deta
	element_div(purk3,purk3,skI1_4); //h3^deta/skI1_4
	element_pow_zn(purk4,h1,deta);   //h1^deta
	element_pow_zn(purk5,h2,deta);   //h2^deta
	element_div(purk5,purk5,skI1_3); //h2^deta/skI1_3
	element_pow_zn(urk1,purk4,I1);   //purk4^I1
	element_mul(urk1,urk1,skI_1);    //purk4^I1*skI_1
	element_mul(urk1,purk1,urk1);    //purk1*purk4^I1*skI_1
	element_mul(urk2,purk2,skI_2);   
	element_mul(urk3,purk3,skI_4);
	element_pow_zn(G1temp1,purk4,I);
	element_pow_zn(G1temp2,purk4,I1);
	element_div(urk4,G1temp1,G1temp2);
	element_mul(urk5,purk5,skI_3);
	time2=get_time();
	turkg[i]=time2-time1;
//	byte_p=element_length_in_bytes(urk1)+element_length_in_bytes(urk2)+element_length_in_bytes(urk3)+element_length_in_bytes(urk4)+element_length_in_bytes(urk5);
//	printf("The length of the update re-encryption key is %d.\n",byte_p);
//	printf("the time of generating update re-encryption urk_I-I1 is %f s.\n\n",time2-time1);

	//generation of update ciphertext
//	printf("--------updating ciphertext---------\n");
	time1=get_time();
	//verify the ciphertext
	//verify the condition
	element_pow_zn(G1temp1,u,w);
	element_mul(G1temp1,G1temp1,v);               //u^w*v
	pairing_apply(GTtemp1,G1temp1,CI1,pairing);   //e(g^s,u^w*v)
	pairing_apply(GTtemp2,g,CI4,pairing);         //e(g,(u^w*v)^s)
	if(!element_cmp(GTtemp1,GTtemp2))
		check=1;
	//veriry the I,w,svk
	element_pow_zn(G1temp1,h1,I);
	element_pow_zn(G1temp2,h2,w);
	element_mul(G1temp1,G1temp1,G1temp2);
	element_pow_zn(G1temp2,h3,haxi_CI0);
	element_mul(G1temp1,G1temp1,G1temp2);
	element_mul(G1temp1,G1temp1,g3);         //h1^I*h2^w*h3^CI0*g3
	pairing_apply(GTtemp1,g,CI5,pairing);    //e(g,CI5)
	pairing_apply(GTtemp2,CI1,G1temp1,pairing);  //e(g^s,h1^I*h2^w*h3^CI0*g3)
	if(!element_cmp(GTtemp1,GTtemp2))
		check+=1;
	//veriry signature
	pairing_apply(GTtemp1,g,CI6,pairing);
	pairing_apply(GTtemp2,CI0,haxi_CI,pairing);
	if(!element_cmp(GTtemp1,GTtemp2))
		check+=1;
	if(check<3)
		printf("The original ciphertext is invalid, aborts!\n");
	else
		{
//			printf("The verification of original ciphertext successes.\n");
			pairing_apply(GTtemp1,urk2,CI5,pairing);   //e(urk2,CI5)
			element_pow_zn(G1temp1,urk3,haxi_CI0);     //urk3^svk
			element_mul(G1temp1,urk1,G1temp1);         //urk1*urk3^svk
			element_mul(G1temp1,G1temp1,urk4);         //urk1*urk3^svk*urk4
			element_pow_zn(G1temp2,urk5,w);            //urk5^w
			element_mul(G1temp1,G1temp1,G1temp2);      //urk1*urk3^svk*urk4*urk5^w
			pairing_apply(GTtemp2,G1temp1,CI1,pairing); //e(urk1*urk3^svk*urk4*urk5^w,CI1)
			element_div(CI1_2,GTtemp1,GTtemp2);           //e(urk2,CI5)/e(urk1*urk3^svk*urk4*urk5^w,CI1)
			element_mul(CI1_2,CI2,CI1_2);                   //CI1_2=CI2*e(urk2,CI5)/e(urk1*urk3^svk*urk4*urk5^w,CI1)
			element_set(CI1_0,CI0);
			element_set(CI1_1,CI1);
			element_set(CI1_4,CI4);
			element_set(CI1_5,CI5);
			element_set(CI1_6,CI6);
			element_set(haxi_CI1_0,haxi_CI0);
			element_set(haxi_CI1,haxi_CI);
			time2=get_time();
			ture[i]=time2-time1;
//			byte_p=element_length_in_bytes(CI1_0)+element_length_in_bytes(CI1_1)+element_length_in_bytes(CI1_2)+element_length_in_bytes(CI1_4)+element_length_in_bytes(CI1_5)+element_length_in_bytes(CI1_6);
//			printf("The length of the updated ciphertext is %d.\n",byte_p);
//			printf("the time of updating ciphertext is %f s\n\n",time2-time1);
		}

	//decryption of updated ciphertext CI1
//	printf("--------------Decrypting updated ciphertext CI1 for cida---------\n");
	time1=get_time();
	//verify the ciphertext
	//verify the condition
	element_pow_zn(G1temp1,u,w);
	element_mul(G1temp1,G1temp1,v);               //u^w*v
	pairing_apply(GTtemp1,G1temp1,CI1_1,pairing);   //e(g^s,u^w*v)
	pairing_apply(GTtemp2,g,CI1_4,pairing);         //e(g,(u^w*v)^s)
	if(!element_cmp(GTtemp1,GTtemp2))
		check=1;
	//veriry the I,w,svk
	element_pow_zn(G1temp1,h1,I);                  //Here I is still the original identity I=(IDi||t), not I1=(IDi||t1)
	element_pow_zn(G1temp2,h2,w);
	element_mul(G1temp1,G1temp1,G1temp2);
	element_pow_zn(G1temp2,h3,haxi_CI1_0);
	element_mul(G1temp1,G1temp1,G1temp2);
	element_mul(G1temp1,G1temp1,g3);         //h1^I*h2^w*h3^CI1_0*g3
	pairing_apply(GTtemp1,g,CI1_5,pairing);    //e(g,CI5)
	pairing_apply(GTtemp2,CI1_1,G1temp1,pairing);  //e(g^s,h1^I*h2^w*h3^CI1_0*g3)
	if(!element_cmp(GTtemp1,GTtemp2))
		check+=1;
	//veriry signature
	pairing_apply(GTtemp1,g,CI1_6,pairing);
	pairing_apply(GTtemp2,CI1_0,haxi_CI1,pairing);
	if(!element_cmp(GTtemp1,GTtemp2))
		check+=1;
	if(check<3)
		printf("The updated ciphertext is invalid, aborts!\n");
	else
		{
//			printf("The verification of updated ciphertext successes.\n");
			pairing_apply(GTtemp1,skI1_2,CI1_5,pairing);    //e(skI1_2,CI1_5)
			element_pow_zn(G1temp1,skI1_4,haxi_CI1_0);      //skI1_4^haxi_CI1_0
			element_mul(G1temp1,skI1_1,G1temp1);
			element_pow_zn(G1temp2,skI1_3,w);
			element_mul(G1temp1,G1temp1,G1temp2);
			pairing_apply(GTtemp2,G1temp1,CI1_1,pairing);
			element_div(p,GTtemp1,GTtemp2);
			element_mul(p,CI1_2,p);
			if(element_cmp(cida,p))
				printf("The decryption of updated ciphertext fails, please check the codes.\n");
			else
				{
//					printf("Decryption of updated ciphertext successes.\n");
					time2=get_time();
					td3[i]=time2-time1;
//					element_printf("The plaintext after decrypting updated ciphertext is p = %B\n",p);
//					printf("the time of decrypting updated ciphertext is %f s\n\n",time2-time1);	
				}
		}

	T_s+=ts[i];
	T_kgI+=tkgI[i];
	T_kgI1+=tkgI1[i];
	T_e+=te[i];
	T_od+=tod[i];
	T_drkg+=tdrkg[i];
	T_dre+=tdre[i];
	T_dd+=tdd[i];
	T_urkg+=turkg[i];
	T_ure+=ture[i];
	T_d3+=td3[i];

	}     //cycle end

	printf(">>>the time of setup is: %f ms\n",1000*T_s/CHISHU);
	printf(">>>the time of key generation for I is: %f ms\n",1000*T_kgI/CHISHU);
	printf(">>>the time of encryption (original ciphertext) is: %f ms\n",1000*T_e/CHISHU);
	printf(">>>the time of decryption for data owner is: %f ms\n",1000*T_od/CHISHU);
	printf(">>>the time of re-encryption key generation for delegation is: %f ms\n",1000*T_drkg/CHISHU);
	printf(">>>the time of re-encrypt for delegation is: %f ms\n",1000*T_dre/CHISHU);
	printf(">>>the time of decryption for requester is: %f ms\n",1000*T_dd/CHISHU);
	printf(">>>the time of key generation for new identity I1 is: %f ms\n",1000*T_kgI1/CHISHU);
	printf(">>>the time of re-encryption key generation for update is: %f ms\n",1000*T_urkg/CHISHU);
	printf(">>>the time of re-encrypt for update is: %f ms\n",1000*T_ure/CHISHU);
	printf(">>>the time of decryption for updated ciphertext is: %f ms\n",1000*T_d3/CHISHU);

	//release RAM
	element_clear(g);
	element_clear(g1);
	element_clear(g2);
	element_clear(g3);
	element_clear(h1);
	element_clear(h2);
	element_clear(h3);
	element_clear(u);
	element_clear(v);
	element_clear(x);
	element_clear(msk);
	element_clear(I);
	element_clear(r);
	element_clear(skI_1);
	element_clear(skI_2);
	element_clear(skI_3);
	element_clear(skI_4);
//	element_clear(rw);
//	element_clear(rI);
//	element_clear(skIw_1);
//	element_clear(skIw_2);
//	element_clear(skIw_3);
	element_clear(G1temp1);
	element_clear(cida);
	element_clear(s);
	element_clear(ssk);
	element_clear(svk);
	element_clear(CI0);
	element_clear(CI1);
	element_clear(CI2);
	element_clear(haxi_CI);
	element_clear(CI4);
	element_clear(haxi_CI0);
	element_clear(G1temp2);
	element_clear(CI5);
	element_clear(CI6);
	element_clear(GTtemp1);
	element_clear(GTtemp2);
	element_clear(p);
	element_clear(J);
	element_clear(rJ);
//	element_clear(skJw_1);
//	element_clear(skJw_2);
//	element_clear(skJw_3);
	element_clear(skJ_1);
	element_clear(skJ_2);
	element_clear(skJ_3);
	element_clear(skJ_4);
	element_clear(Ro);
	element_clear(t);
	element_clear(CIDA);          //CIDA
	element_clear(pdrk1);
	element_clear(haxi_CIDA);     //H(CIDA)
	element_clear(pdrk2);
	element_clear(pdrk3);
	element_clear(pdrk4);
	element_clear(drk0);
	element_clear(drk1);
	element_clear(drk2);
	element_clear(drk3);
	element_clear(haxi_drk0);
	element_clear(haxi_drk);
	element_clear(drk4);
	element_clear(ssk_drk);
	element_clear(svk_drk);
	element_clear(CJ0);
	element_clear(CJ1);
	element_clear(CJ2);
	element_clear(CJ4);
	element_clear(CJ5);
	element_clear(CJ6);
	element_clear(haxi_CJ0);
	element_clear(haxi_CJ);
	element_clear(p2);
	element_clear(I1);
	element_clear(r1);
//	element_clear(rI1);
	element_clear(skI1_1);
	element_clear(skI1_2);
	element_clear(skI1_3);
	element_clear(skI1_4);
//	element_clear(skI1w_1);
//	element_clear(skI1w_2);
//	element_clear(skI1w_3);
	element_clear(deta);
	element_clear(purk1);
	element_clear(purk2);
	element_clear(purk3);
	element_clear(purk4);
	element_clear(purk5);
	element_clear(urk1);
	element_clear(urk2);
	element_clear(urk3);
	element_clear(urk4);
	element_clear(urk5);
	element_clear(CI1_0);
	element_clear(CI1_1);
	element_clear(CI1_2);
	element_clear(CI1_4);
	element_clear(CI1_5);
	element_clear(CI1_6);
	element_clear(haxi_CI1_0);
	element_clear(haxi_CI1);

	pairing_clear(pairing);
	return 0;

}