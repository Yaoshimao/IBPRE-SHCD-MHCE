//Yao [9] for ciphertext update with ciphertext optimality
//GA06, IBPRE

#include<pbc.h>
#include<pbc_time.h>
#define CHISHU 1
int main()
{
	pairing_t peidui;//e:G1*G1->GT
	//the parameters in setup phase
	element_t s,P,Ppub; //msk=s,P is the generator of G1, Ppub=P^s
	//the parameters in keygen phase
	element_t Qu1,Su1; //Su1=Qu1^s,Qu=H1(ID1)
	element_t Qu2,Su2; //Su2=Qu2^s,Qu=H1(ID2)
	//the parameters in encryption phase
	element_t r,C1,C2,T1,m;//C1=P^r, T1=e(Ppub,Qu^r),C2=m*T1=m*e(P^s,Qu^r)
	//the parameters in decryption1 phase
	element_t T2,m1; //T2=e(Qu^s,P^r),m1 will be the result of decrypting the C_id1
	//the parameters in RKgen phase
	element_t X3,R3;//R3=X3/Su1,X3=H2(K_AB)
	//the parameters in REncryption phase 
	element_t C21,C22;
	//the parameters in decryption2 phase
	element_t T3; //T3=e(C1,H2(X))=e(g^r,X2)
	element_t newSu1,newQu1; //new identity for user
	element_t R1,R2;
	element_t r1;
	double time0,time1,time2,time3,tG;
	double ts[CHISHU],tkg[CHISHU],te[CHISHU],td1[CHISHU],td2[CHISHU],trkg1[CHISHU],trkg2[CHISHU],trk1[CHISHU],trk2[CHISHU],tH[CHISHU];
	double T_s,T_kg,T_e,T_d1,T_d2,T_rkg1,T_rkg2,T_rk1,T_rk2,T_H;
	int i;
	T_s=0;T_kg=0;T_e=0;T_d1=0;T_d2=0;T_rkg1=0;T_rkg2=0;T_rk1=0;T_rk2=0;T_H=0;
	
	a_param_input(peidui);
	element_init_Zr(s,peidui);  //s belongs to Zp
	element_init_G1(P,peidui);  //P belonges to G1
	element_init_G1(Ppub,peidui); //Ppub=P^s also belongs to G1
	element_init_G1(Qu1,peidui); //Qu1=H1(ID1) belongs to G1
	element_init_G1(Su1,peidui); //Su1=Qu1^s belongs to G1
	element_init_G1(Qu2,peidui); //Qu2=H1(ID2) belongs to G1
	element_init_G1(Su2,peidui); //Su2=Qu2^s belongs to G1
	element_init_Zr(r,peidui); //random r from Zp
	element_init_G1(C1,peidui); //the first part of ciphertext C_id1 belongs to G1
	element_init_GT(C2,peidui); //the second part of ciphertext C_id1 belongs to GT
	element_init_GT(T1,peidui);//T1 belongs to GT
	element_init_GT(m,peidui); //m belongs to GT
	element_init_GT(T2,peidui);//T2 belongs to GT
	element_init_GT(m1,peidui);//m1 belongs to GT, used to check m1=m
	element_init_G1(X3,peidui); //X3=H3(K_AB||A->B) belong to G1, but here is chosen randomly to replace hash function
	element_init_G1(R3,peidui); //the third part of the re-encryption key,R3=Su1^-1*H3(K_AB||A->B)
	element_init_GT(C22,peidui); //the second part of the re-encrypted ciphertext C_id2
	element_init_GT(T3,peidui); //the pairing in Decryption2, T3=e(C1,H2(X1)=e(C1,X2)
	element_init_G1(newSu1,peidui);
	element_init_G1(newQu1,peidui);
	element_init_G1(R1,peidui);
	element_init_GT(R2,peidui);
	element_init_Zr(r1,peidui);
	element_init_G1(C21,peidui);

	if(!pairing_is_symmetric(peidui))
	{
		fprintf(stderr,"only works with symmetric pairing\n");
		exit(1);
	}
	
	for(i=0;i<CHISHU;i++)
	{
		
//	printf("--------Setup-------\n");
	time1=get_time();
	element_random(s);//master secret key
	element_random(P);//generator
	element_pow_zn(Ppub,P,s);//public params,Ppub=P^s
	time2=get_time();
	ts[i]=time2-time1;
//	element_printf(">>>the generator of the G1 is: %B\n",P);
//	element_printf(">>>the master secret key is: %B\n",s);
//	element_printf(">>>the public params is: %B\n",Ppub);
//	printf(">>>the time of setup is: %fs\n",ts);

//	printf("--------KeyGen(Extract)--------\n");
	time1=get_time();
	element_from_hash(Qu1,"Alice",5); 
	time3=get_time();
//	element_random(Qu1);//id1's public key
	element_pow_zn(Su1,Qu1,s);//Su1=Qu1^s
	time2=get_time();
	tH[i]=time3-time1;
	tkg[i]=time2-time1;
	element_from_hash(Qu2,"Bob",3); 
	element_pow_zn(Su2,Qu2,s);//Su2=Qu2^s
//	element_printf(">>>the public key of the identity is: %B\n",Qu1);
//	element_printf(">>>the private key of the identity is: %B\n",Su1);
//	printf(">>>the time of KeyGen is: %fs\n",tkg[i]);

//	printf("-------------encryption(C_id1=(C1,C2)--------\n");
	element_random(m);// input a message m
	time1=get_time();
	element_random(r);
	element_pow_zn(C1,P,r);//C1=P^r,the first part of the ciphertext C_id1
	pairing_apply(T1,Ppub,Qu1,peidui);//T1=e(Ppub,Qu1)
	element_pow_zn(T1,T1,r);//T1=T1^r=e(Ppub,Qu1)^r
	element_mul(C2,m,T1); //C2=m*e(g^s,H1(id1)^r)
	time2=get_time();
	te[i]=time2-time1;    
//	element_printf(">>>The Plaintext is: %B\n",m);
//	element_printf(">>>The first part of the ciphertext is: %B\n",C1);
//	element_printf(">>>The second part of the ciphtertext is: %B\n",C2);
//	printf(">>>the time of encryption is: %fs\n",te[i]);

//	printf("--------decryption1--------\n");
	time1=get_time();
	pairing_apply(T2,C1,Su1,peidui);//T2=e(C1,Su1)
	element_div(m1,C2,T2); //m1=C2/T2=m*e(g^s,H1(id1)^r)/e(g^r,H1(id1)^s)
	time2=get_time();
	td1[i]=time2-time1;
//	element_printf(">>>the plaintext after decrypting is: %B\n",m1);
//	if (!element_cmp(m,m1)) printf("The decryption for original ciphertext is right\n");
//	printf(">>>the time of decrypt the original ciphertext is: %fs\n",td1[i]);

//	printf("----------re-encryption key generation(rk=(R1,R2,R3)--------\n");
	time0=get_time();
	element_random(X3);//X3 for replacing H2(K_AB||A->B)
	time1=get_time();
	pairing_apply(T1,Su1,Qu2,peidui);//T1=e(Su1,Qu2)=K_AB
	element_mul(R3,X3,Su1); //R3=Su1*H2(X)
	pairing_apply(T2,C1,R3,peidui); //T2=rk_A->B=e(C1,H2(K_AB||A||B)*Su1)
	time2=get_time();
	tG=time1-time0;
	trkg1[i]=time2-time1+tG;
//	element_printf(">>>The re-encryption key is: %B\n",T2);
//	printf(">>>the time of re-encryption key generation is: %fs\n",trkg1[i]);


//	printf("-------re-encryption ciphertext(c_id2=(C1,C2*e(C1,R3),R1,R2)------\n");
	time1=get_time();
	element_div(C22,C2,T2); //C22=C2/T2=m*e(g^s,Qu1^r)/e(g^r,H2(X)*Su1)
	time2=get_time();
	trk1[i]=time2-time1;
//	element_printf(">>>The first part of the re-encrypted ciphertext is: %B\n",C1);
//	element_printf(">>>The second part of the re-encrypted ciphertext  is: %B\n",C22);
//	printf(">>>the time of re-encryption is: %fs\n",trk1[i]);

//	printf("--------------decryption2 -----------\n");
	time1=get_time();
	pairing_apply(T2,Su2,Qu1,peidui);//T2=e(Su2,Qu1)=K_BA
	pairing_apply(T3,C1,X3,peidui);//T3=e(C1,X3)
	element_mul(m1,C22,T3);
	time2=get_time();
	td2[i]=time2-time1+tG;
//	element_printf(">>>the requester decrypt the re-encrypted ciphertext to get the plaintext is: %B\n",m1);

//	if (!element_cmp(m,m1)) printf("The decryption for delegated ciphertext is right!\n");
//	printf(">>>the time of re-encryption is: %fs\n",td2[i]);


//	printf("----------re-encryption key generation(rk=(R1,R2,R3)--------\n");
	element_from_hash(newQu1,"newAlice",8); 
	element_pow_zn(newSu1,newQu1,s);//newSu1=newQu1^s
	time1=get_time();
	element_random(r1);//C21=g^r1=g^r*(g^r1/g^r)
	element_pow_zn(R1,P,r1);
	pairing_apply(T1,Ppub,newQu1,peidui);//T1=e(g^s,H1(id1'))
	element_pow_zn(T1,T1,r1);  //T1=e(g^s,H1(id1'))^r1
	pairing_apply(T2,C1,Su1,peidui);  //T2=e(g^r,H1(Su1)^s)
	element_div(R2,T1,T2);   //R2=e(g^s,H1(id1'))^r1/e(g^r,H1(Su1)^s)
	time2=get_time();
	trkg2[i]=time2-time1;
//	element_printf(">>>The first part of the re-encryption key for updating is: %B\n",R1);
//	element_printf(">>>The second part of the re-encryption key for updating is: %B\n",R2);
//	printf(">>>the time of re-encryption key generation for updating is: %fs\n",trkg2[i]);

//	printf("-------re-encryption ciphertext for updating(c_id1'=(R1,C2*R2)------\n");
	time1=get_time();
	element_set(C1,R1);     //first part of new ciphertext
	element_mul(C2,C2,R2);//second part of new ciphertext
	time2=get_time();
	trk2[i]=time2-time1;
//	element_printf(">>>The first part of the updated ciphertext is: %B\n",C1);
//	element_printf(">>>The second part of the updated ciphertext  is: %B\n",C2);
//	printf(">>>the time of re-encryption for updating is: %fs\n",trk2[i]);


//	printf("--------decryption1--------\n");
	element_set(Su1,newSu1);
//	time1=get_time();
	pairing_apply(T2,C1,Su1,peidui);//T2=e(C21,newSu1)
	element_div(m1,C2,T2); //m1=C12/T2=m*e(g^s,H1(id1')^r1)/e(g^r,H1(id1)^s)
//	time2=get_time();
//	td1[i]=time2-time1;
//	element_printf(">>>the plaintext after decrypting is: %B\n",m1);
//	if (!element_cmp(m,m1)) printf("The decryption for updated ciphertext is right!\n");
//	printf(">>>the time of decrypt is: %fs\n",td1[i]);
	T_H+=tH[i];
	T_s+=ts[i];
	T_kg+=tkg[i];
	T_e+=te[i];
	T_d1+=td1[i];
	T_rkg1+=trkg1[i];
	T_rk1+=trk1[i];
	T_d2+=td2[i];
	T_rkg2+=trkg2[i];
	T_rk2+=trk2[i];
	}
	printf(">>>the time of hashing identity to public key is: %f ms\n",1000*T_H/CHISHU);
	printf(">>>the time of setup is: %f ms\n",1000*T_s/CHISHU);
	printf(">>>the time of key generation is: %f ms\n",1000*T_kg/CHISHU);
	printf(">>>the time of encryption is: %f ms\n",1000*T_e/CHISHU);
	printf(">>>the time of decryption for user is: %f ms\n",1000*T_d1/CHISHU);
	printf(">>>the time of re-encryption key generation for delegation is: %f ms\n",1000*T_rkg1/CHISHU);
	printf(">>>the time of re-encrypt for delegation is: %f ms\n",1000*T_rk1/CHISHU);
	printf(">>>the time of decryption for requester is: %f ms\n",1000*T_d2/CHISHU);
	printf(">>>the time of re-encryption key generation for update is: %f ms\n",1000*T_rkg2/CHISHU);
	printf(">>>the time of re-encrypt for update is: %f ms\n",1000*T_rk2/CHISHU);

	
	element_clear(P);
	element_clear(s);
	element_clear(Ppub);
	element_clear(Qu1);
	element_clear(Su1);
	element_clear(T1);
	element_clear(r);
	element_clear(C1);
	element_clear(C2);
	element_clear(m);
	element_clear(T2);
	element_clear(m1);
	element_clear(X3);
	element_clear(R3);
	element_clear(C22);
	element_clear(C21);
	element_clear(r1);
	element_clear(R1);
	element_clear(R2);
	element_clear(T3);
	element_clear(newSu1);
	element_clear(newQu1);
	pairing_clear(peidui);
	return 0;


}