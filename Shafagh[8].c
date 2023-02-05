//Shafach et al. 2017
//for delegation, AFGH05
//for update, BBS98
#include<pbc.h>
#include<pbc_time.h>
#define CHISHU 1
int main()
{
	pairing_t peidui;
	element_t P,Z;
	element_t a,pka;
	element_t r,m,C11,C12;
	element_t inv,d,T1,m1;
	element_t b,pkb;
	element_t R;
	element_t C21,C22;
	element_t a1,pka1;
	element_t R1;
	int i;
	double time1,time2;
	double ts[CHISHU],tkg[CHISHU],te[CHISHU],td1[CHISHU];
	double td2[CHISHU],trkg1[CHISHU],trkg2[CHISHU],trk1[CHISHU],trk2[CHISHU];
	double T_s,T_kg,T_e,T_d1;
	double T_d2,T_rkg1,T_rkg2,T_rk1,T_rk2;
	T_s=0;T_kg=0;T_e=0;T_d1=0;
	T_d2=0;T_rkg1=0;T_rkg2=0;T_rk1=0;T_rk2=0;

	a_param_input(peidui); 
	element_init_G1(P,peidui);
	element_init_GT(Z,peidui);
	element_init_Zr(a,peidui);
	element_init_G1(pka,peidui);
	element_init_Zr(r,peidui);
	element_init_GT(m,peidui);
	element_init_GT(C11,peidui);
	element_init_G1(C12,peidui);
	element_init_Zr(inv,peidui);
	element_init_G1(d,peidui);
	element_init_GT(T1,peidui);
	element_init_GT(m1,peidui);
	element_init_Zr(b,peidui);
	element_init_G1(pkb,peidui);
	element_init_G1(R,peidui);
	element_init_GT(C21,peidui);
	element_init_GT(C22,peidui);
	element_init_Zr(a1,peidui);
	element_init_G1(pka1,peidui);
	element_init_Zr(R1,peidui);


	if(!pairing_is_symmetric(peidui))
	{
		fprintf(stderr,"only works with symmetric pairing\n");
		exit(1);
	}

	printf("Shafagh(ElGamal) Scheme\n");
	
	for(i=0;i<CHISHU;i++)

{
		
//	printf("--------Setup-------\n");
	time1=get_time();
	element_random(P);//generator
	pairing_apply(Z,P,P,peidui);  //Z=e(g,g)
	time2=get_time();
	ts[i]=time2-time1;
//	element_printf(">>>the generator of the G1 is P= %B\n",P);
//	printf(">>>the time of setup is: %fs\n",ts);

//	printf("--------KeyGen(Extract)--------\n");
	time1=get_time();
	element_random(a);
	element_pow_zn(pka,P,a);
	time2=get_time();
	tkg[i]=time2-time1;
//	element_printf(">>>the private key of user is: %B\n",a);
//	element_printf(">>>the public key of user is: %B\n",pka);
//	printf(">>>the time of KeyGen is: %fs\n",tkg[i]);
	
//	printf("---------encryption(C1=(C11,C12)--------\n");
	element_random(m);// input a message m
	time1=get_time();
	element_random(r);
	element_pow_zn(C11,Z,r); //C1=e(g,g)^r
	element_mul(C11,C11,m);//C1=m*e(g,g)^r,the first part of the ciphertext C1
	element_pow_zn(C12,pka,r);//C12=g^ar
	time2=get_time();
	te[i]=time2-time1;
//	element_printf(">>>The Plaintext is: %B\n",m);
//	element_printf(">>>The first part of the ciphertext is: %B\n",C11);
//	element_printf(">>>The second part of the ciphtertext is: %B\n",C12);
//	printf(">>>the time of encryption is: %fs\n",te[i]);
	

//	printf("--------decryption--------\n");
	time1=get_time();
	element_invert(inv,a);  //inv=1/a
	element_pow_zn(d,P,inv);//d=g^1/a
	pairing_apply(T1,C12,d,peidui);//T1=e(g^ar,g^1/a)=Z^r
	element_div(m1,C11,T1); //m1=m*Z^r/e(g^ar,g^1/a)
	time2=get_time();
	td1[i]=time2-time1;
//	element_printf(">>>the plaintext after decryption is: %B\n",m1);
//	if (!element_cmp(m,m1)) printf("The decryption for original ciphertext is right\n");
//	printf(">>>the time of decrypt the original ciphertext is: %fs\n",td1[i]);

	//requester's key pair
	element_random(b);//requester's private key
	element_random(pkb);//requester's public key
	element_pow_zn(pkb,P,b);//pkb=g^b
//	element_printf("the requester's public key is : %B\n",pkb);
//	element_printf("the requester's private key is : %B\n",b);


//	printf("----------re-encryption key generation(rk=g^b/a--------\n");

	time1=get_time();
	element_invert(inv,a);//inv=1/a
	element_pow_zn(R,pkb,inv);  //R=(g^b)^1/a=g^b/a
	time2=get_time();
	trkg1[i]=time2-time1;
//	element_printf(">>>The re-encryption key is: %B\n",R);
//	printf(">>>the time of re-encryption key generation is: %fs\n",trkg1[i]);


//	printf("-------re-encryption ciphertext(c2=(C21,C22)------\n");
	time1=get_time();
	pairing_apply(C22,C12,R,peidui);//T1=e(g^ar,g^b/a)=Z^br
	element_set(C21,C11);  //C21=C11
	time2=get_time();
	trk1[i]=time2-time1;
//	element_printf(">>>The first part of the re-encrypted ciphertext is: %B\n",C21);
//	element_printf(">>>The second part of the re-encrypted ciphertext  is: %B\n",C22);

//	printf(">>>the time of re-encryption is: %fs\n",trk1[i]);


//	printf("--------------decryption2 -----------\n");
	time1=get_time();
	element_invert(inv,b);// inv=1/b
	element_pow_zn(T1,C22,inv);//T1=(Z^br)^1/b
	element_div(m1,C21,T1); //m1=m*Z^r/(Z^br)^(1/b)
	time2=get_time();
	td2[i]=time2-time1;
//	element_printf(">>>the requester decrypt the re-encrypted ciphertext to get the plaintext is: %B\n",m1);
//	if (!element_cmp(m,m1)) printf("The decryption of C21 is right!\n");
//	printf(">>>the time of re-encryption is: %fs\n",td2[i]);


//	printf("---------update ciphertext re-encryption key generation----------\n");
	element_random(a1);//new private key
	element_pow_zn(pka1,P,a1);//new public key
	time1=get_time();
	element_div(R1,a1,a);  //R=a1/a
	time2=get_time();
	trkg2[i]=time2-time1;
//	printf(">>>the time of update key generation is %fd\n",rkg2[i]);


//	printf("--------re-encrypt ciphertext for updating------\n");
	time1=get_time();
	element_pow_zn(C12,C12,R1);//C12=(g^ar)^(a1/a)=g^a1r
	time2=get_time();
	trk2[i]=time2-time1;
//	element_printf("the first part of updated ciphertext is %B\n",C11);
//	element_printf("the second part of updated ciphertext is %B\n",C12);
//	printf(">>>the time of updating ciphertext is :%B\n",trk2[i]);

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
	element_clear(a);
	element_clear(pka);
	element_clear(r);
	element_clear(Z);
	element_clear(C11);
	element_clear(C12);
	element_clear(inv);
	element_clear(d);
	element_clear(T1);
	element_clear(m);
	element_clear(m1);
	element_clear(b);
	element_clear(pkb);
	element_clear(R);
	element_clear(C21);
	element_clear(C22);
	element_clear(a1);
	element_clear(pka1);
	element_clear(R1);
	
	pairing_clear(peidui);
	return 0;

}