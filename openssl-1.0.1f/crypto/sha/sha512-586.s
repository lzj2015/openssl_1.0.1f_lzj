.file	"sha512-586.s"
.text
.globl	_sha512_block_data_order
.align	4
_sha512_block_data_order:
L_sha512_block_data_order_begin:
	pushl	%ebp
	pushl	%ebx
	pushl	%esi
	pushl	%edi
	movl	20(%esp),%esi
	movl	24(%esp),%edi
	movl	28(%esp),%eax
	movl	%esp,%ebx
	call	L000pic_point
L000pic_point:
	popl	%ebp
	leal	L001K512-L000pic_point(%ebp),%ebp
	subl	$16,%esp
	andl	$-64,%esp
	shll	$7,%eax
	addl	%edi,%eax
	movl	%esi,(%esp)
	movl	%edi,4(%esp)
	movl	%eax,8(%esp)
	movl	%ebx,12(%esp)
	movl	L_OPENSSL_ia32cap_P$non_lazy_ptr-L001K512(%ebp),%edx
	btl	$26,(%edx)
	jnc	L002loop_x86
	movq	(%esi),%mm0
	movq	8(%esi),%mm1
	movq	16(%esi),%mm2
	movq	24(%esi),%mm3
	movq	32(%esi),%mm4
	movq	40(%esi),%mm5
	movq	48(%esi),%mm6
	movq	56(%esi),%mm7
	subl	$80,%esp
.align	4,0x90
L003loop_sse2:
	movq	%mm1,8(%esp)
	movq	%mm2,16(%esp)
	movq	%mm3,24(%esp)
	movq	%mm5,40(%esp)
	movq	%mm6,48(%esp)
	movq	%mm7,56(%esp)
	movl	(%edi),%ecx
	movl	4(%edi),%edx
	addl	$8,%edi
	bswap	%ecx
	bswap	%edx
	movl	%ecx,76(%esp)
	movl	%edx,72(%esp)
.align	4,0x90
L00400_14_sse2:
	movl	(%edi),%eax
	movl	4(%edi),%ebx
	addl	$8,%edi
	bswap	%eax
	bswap	%ebx
	movl	%eax,68(%esp)
	movl	%ebx,64(%esp)
	movq	40(%esp),%mm5
	movq	48(%esp),%mm6
	movq	56(%esp),%mm7
	movq	%mm4,%mm1
	movq	%mm4,%mm2
	psrlq	$14,%mm1
	movq	%mm4,32(%esp)
	psllq	$23,%mm2
	movq	%mm1,%mm3
	psrlq	$4,%mm1
	pxor	%mm2,%mm3
	psllq	$23,%mm2
	pxor	%mm1,%mm3
	psrlq	$23,%mm1
	pxor	%mm2,%mm3
	psllq	$4,%mm2
	pxor	%mm1,%mm3
	paddq	(%ebp),%mm7
	pxor	%mm2,%mm3
	pxor	%mm6,%mm5
	movq	8(%esp),%mm1
	pand	%mm4,%mm5
	movq	16(%esp),%mm2
	pxor	%mm6,%mm5
	movq	24(%esp),%mm4
	paddq	%mm5,%mm3
	movq	%mm0,(%esp)
	paddq	%mm7,%mm3
	movq	%mm0,%mm5
	movq	%mm0,%mm6
	paddq	72(%esp),%mm3
	psrlq	$28,%mm5
	paddq	%mm3,%mm4
	psllq	$25,%mm6
	movq	%mm5,%mm7
	psrlq	$6,%mm5
	pxor	%mm6,%mm7
	psllq	$5,%mm6
	pxor	%mm5,%mm7
	psrlq	$5,%mm5
	pxor	%mm6,%mm7
	psllq	$6,%mm6
	pxor	%mm5,%mm7
	subl	$8,%esp
	pxor	%mm6,%mm7
	movq	%mm0,%mm5
	por	%mm2,%mm0
	pand	%mm2,%mm5
	pand	%mm1,%mm0
	por	%mm0,%mm5
	paddq	%mm5,%mm7
	movq	%mm3,%mm0
	movb	(%ebp),%dl
	paddq	%mm7,%mm0
	addl	$8,%ebp
	cmpb	$53,%dl
	jne	L00400_14_sse2
	movq	40(%esp),%mm5
	movq	48(%esp),%mm6
	movq	56(%esp),%mm7
	movq	%mm4,%mm1
	movq	%mm4,%mm2
	psrlq	$14,%mm1
	movq	%mm4,32(%esp)
	psllq	$23,%mm2
	movq	%mm1,%mm3
	psrlq	$4,%mm1
	pxor	%mm2,%mm3
	psllq	$23,%mm2
	pxor	%mm1,%mm3
	psrlq	$23,%mm1
	pxor	%mm2,%mm3
	psllq	$4,%mm2
	pxor	%mm1,%mm3
	paddq	(%ebp),%mm7
	pxor	%mm2,%mm3
	pxor	%mm6,%mm5
	movq	8(%esp),%mm1
	pand	%mm4,%mm5
	movq	16(%esp),%mm2
	pxor	%mm6,%mm5
	movq	24(%esp),%mm4
	paddq	%mm5,%mm3
	movq	%mm0,(%esp)
	paddq	%mm7,%mm3
	movq	%mm0,%mm5
	movq	%mm0,%mm6
	paddq	72(%esp),%mm3
	psrlq	$28,%mm5
	paddq	%mm3,%mm4
	psllq	$25,%mm6
	movq	%mm5,%mm7
	psrlq	$6,%mm5
	pxor	%mm6,%mm7
	psllq	$5,%mm6
	pxor	%mm5,%mm7
	psrlq	$5,%mm5
	pxor	%mm6,%mm7
	psllq	$6,%mm6
	pxor	%mm5,%mm7
	subl	$8,%esp
	pxor	%mm6,%mm7
	movq	%mm0,%mm5
	por	%mm2,%mm0
	movq	88(%esp),%mm6
	pand	%mm2,%mm5
	pand	%mm1,%mm0
	movq	192(%esp),%mm2
	por	%mm0,%mm5
	paddq	%mm5,%mm7
	movq	%mm3,%mm0
	movb	(%ebp),%dl
	paddq	%mm7,%mm0
	addl	$8,%ebp
.align	4,0x90
L00516_79_sse2:
	movq	%mm2,%mm1
	psrlq	$1,%mm2
	movq	%mm6,%mm7
	psrlq	$6,%mm6
	movq	%mm2,%mm3
	psrlq	$6,%mm2
	movq	%mm6,%mm5
	psrlq	$13,%mm6
	pxor	%mm2,%mm3
	psrlq	$1,%mm2
	pxor	%mm6,%mm5
	psrlq	$42,%mm6
	pxor	%mm2,%mm3
	movq	200(%esp),%mm2
	psllq	$56,%mm1
	pxor	%mm6,%mm5
	psllq	$3,%mm7
	pxor	%mm1,%mm3
	paddq	128(%esp),%mm2
	psllq	$7,%mm1
	pxor	%mm7,%mm5
	psllq	$42,%mm7
	pxor	%mm1,%mm3
	pxor	%mm7,%mm5
	paddq	%mm5,%mm3
	paddq	%mm2,%mm3
	movq	%mm3,72(%esp)
	movq	40(%esp),%mm5
	movq	48(%esp),%mm6
	movq	56(%esp),%mm7
	movq	%mm4,%mm1
	movq	%mm4,%mm2
	psrlq	$14,%mm1
	movq	%mm4,32(%esp)
	psllq	$23,%mm2
	movq	%mm1,%mm3
	psrlq	$4,%mm1
	pxor	%mm2,%mm3
	psllq	$23,%mm2
	pxor	%mm1,%mm3
	psrlq	$23,%mm1
	pxor	%mm2,%mm3
	psllq	$4,%mm2
	pxor	%mm1,%mm3
	paddq	(%ebp),%mm7
	pxor	%mm2,%mm3
	pxor	%mm6,%mm5
	movq	8(%esp),%mm1
	pand	%mm4,%mm5
	movq	16(%esp),%mm2
	pxor	%mm6,%mm5
	movq	24(%esp),%mm4
	paddq	%mm5,%mm3
	movq	%mm0,(%esp)
	paddq	%mm7,%mm3
	movq	%mm0,%mm5
	movq	%mm0,%mm6
	paddq	72(%esp),%mm3
	psrlq	$28,%mm5
	paddq	%mm3,%mm4
	psllq	$25,%mm6
	movq	%mm5,%mm7
	psrlq	$6,%mm5
	pxor	%mm6,%mm7
	psllq	$5,%mm6
	pxor	%mm5,%mm7
	psrlq	$5,%mm5
	pxor	%mm6,%mm7
	psllq	$6,%mm6
	pxor	%mm5,%mm7
	subl	$8,%esp
	pxor	%mm6,%mm7
	movq	%mm0,%mm5
	por	%mm2,%mm0
	movq	88(%esp),%mm6
	pand	%mm2,%mm5
	pand	%mm1,%mm0
	movq	192(%esp),%mm2
	por	%mm0,%mm5
	paddq	%mm5,%mm7
	movq	%mm3,%mm0
	movb	(%ebp),%dl
	paddq	%mm7,%mm0
	addl	$8,%ebp
	cmpb	$23,%dl
	jne	L00516_79_sse2
	movq	8(%esp),%mm1
	movq	16(%esp),%mm2
	movq	24(%esp),%mm3
	movq	40(%esp),%mm5
	movq	48(%esp),%mm6
	movq	56(%esp),%mm7
	paddq	(%esi),%mm0
	paddq	8(%esi),%mm1
	paddq	16(%esi),%mm2
	paddq	24(%esi),%mm3
	paddq	32(%esi),%mm4
	paddq	40(%esi),%mm5
	paddq	48(%esi),%mm6
	paddq	56(%esi),%mm7
	movq	%mm0,(%esi)
	movq	%mm1,8(%esi)
	movq	%mm2,16(%esi)
	movq	%mm3,24(%esi)
	movq	%mm4,32(%esi)
	movq	%mm5,40(%esi)
	movq	%mm6,48(%esi)
	movq	%mm7,56(%esi)
	addl	$640,%esp
	subl	$640,%ebp
	cmpl	88(%esp),%edi
	jb	L003loop_sse2
	emms
	movl	92(%esp),%esp
	popl	%edi
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret
.align	4,0x90
L002loop_x86:
	movl	(%edi),%eax
	movl	4(%edi),%ebx
	movl	8(%edi),%ecx
	movl	12(%edi),%edx
	bswap	%eax
	bswap	%ebx
	bswap	%ecx
	bswap	%edx
	pushl	%eax
	pushl	%ebx
	pushl	%ecx
	pushl	%edx
	movl	16(%edi),%eax
	movl	20(%edi),%ebx
	movl	24(%edi),%ecx
	movl	28(%edi),%edx
	bswap	%eax
	bswap	%ebx
	bswap	%ecx
	bswap	%edx
	pushl	%eax
	pushl	%ebx
	pushl	%ecx
	pushl	%edx
	movl	32(%edi),%eax
	movl	36(%edi),%ebx
	movl	40(%edi),%ecx
	movl	44(%edi),%edx
	bswap	%eax
	bswap	%ebx
	bswap	%ecx
	bswap	%edx
	pushl	%eax
	pushl	%ebx
	pushl	%ecx
	pushl	%edx
	movl	48(%edi),%eax
	movl	52(%edi),%ebx
	movl	56(%edi),%ecx
	movl	60(%edi),%edx
	bswap	%eax
	bswap	%ebx
	bswap	%ecx
	bswap	%edx
	pushl	%eax
	pushl	%ebx
	pushl	%ecx
	pushl	%edx
	movl	64(%edi),%eax
	movl	68(%edi),%ebx
	movl	72(%edi),%ecx
	movl	76(%edi),%edx
	bswap	%eax
	bswap	%ebx
	bswap	%ecx
	bswap	%edx
	pushl	%eax
	pushl	%ebx
	pushl	%ecx
	pushl	%edx
	movl	80(%edi),%eax
	movl	84(%edi),%ebx
	movl	88(%edi),%ecx
	movl	92(%edi),%edx
	bswap	%eax
	bswap	%ebx
	bswap	%ecx
	bswap	%edx
	pushl	%eax
	pushl	%ebx
	pushl	%ecx
	pushl	%edx
	movl	96(%edi),%eax
	movl	100(%edi),%ebx
	movl	104(%edi),%ecx
	movl	108(%edi),%edx
	bswap	%eax
	bswap	%ebx
	bswap	%ecx
	bswap	%edx
	pushl	%eax
	pushl	%ebx
	pushl	%ecx
	pushl	%edx
	movl	112(%edi),%eax
	movl	116(%edi),%ebx
	movl	120(%edi),%ecx
	movl	124(%edi),%edx
	bswap	%eax
	bswap	%ebx
	bswap	%ecx
	bswap	%edx
	pushl	%eax
	pushl	%ebx
	pushl	%ecx
	pushl	%edx
	addl	$128,%edi
	subl	$72,%esp
	movl	%edi,204(%esp)
	leal	8(%esp),%edi
	movl	$16,%ecx
.long	2784229001
.align	4,0x90
L00600_15_x86:
	movl	40(%esp),%ecx
	movl	44(%esp),%edx
	movl	%ecx,%esi
	shrl	$9,%ecx
	movl	%edx,%edi
	shrl	$9,%edx
	movl	%ecx,%ebx
	shll	$14,%esi
	movl	%edx,%eax
	shll	$14,%edi
	xorl	%esi,%ebx
	shrl	$5,%ecx
	xorl	%edi,%eax
	shrl	$5,%edx
	xorl	%ecx,%eax
	shll	$4,%esi
	xorl	%edx,%ebx
	shll	$4,%edi
	xorl	%esi,%ebx
	shrl	$4,%ecx
	xorl	%edi,%eax
	shrl	$4,%edx
	xorl	%ecx,%eax
	shll	$5,%esi
	xorl	%edx,%ebx
	shll	$5,%edi
	xorl	%esi,%eax
	xorl	%edi,%ebx
	movl	48(%esp),%ecx
	movl	52(%esp),%edx
	movl	56(%esp),%esi
	movl	60(%esp),%edi
	addl	64(%esp),%eax
	adcl	68(%esp),%ebx
	xorl	%esi,%ecx
	xorl	%edi,%edx
	andl	40(%esp),%ecx
	andl	44(%esp),%edx
	addl	192(%esp),%eax
	adcl	196(%esp),%ebx
	xorl	%esi,%ecx
	xorl	%edi,%edx
	movl	(%ebp),%esi
	movl	4(%ebp),%edi
	addl	%ecx,%eax
	adcl	%edx,%ebx
	movl	32(%esp),%ecx
	movl	36(%esp),%edx
	addl	%esi,%eax
	adcl	%edi,%ebx
	movl	%eax,(%esp)
	movl	%ebx,4(%esp)
	addl	%ecx,%eax
	adcl	%edx,%ebx
	movl	8(%esp),%ecx
	movl	12(%esp),%edx
	movl	%eax,32(%esp)
	movl	%ebx,36(%esp)
	movl	%ecx,%esi
	shrl	$2,%ecx
	movl	%edx,%edi
	shrl	$2,%edx
	movl	%ecx,%ebx
	shll	$4,%esi
	movl	%edx,%eax
	shll	$4,%edi
	xorl	%esi,%ebx
	shrl	$5,%ecx
	xorl	%edi,%eax
	shrl	$5,%edx
	xorl	%ecx,%ebx
	shll	$21,%esi
	xorl	%edx,%eax
	shll	$21,%edi
	xorl	%esi,%eax
	shrl	$21,%ecx
	xorl	%edi,%ebx
	shrl	$21,%edx
	xorl	%ecx,%eax
	shll	$5,%esi
	xorl	%edx,%ebx
	shll	$5,%edi
	xorl	%esi,%eax
	xorl	%edi,%ebx
	movl	8(%esp),%ecx
	movl	12(%esp),%edx
	movl	16(%esp),%esi
	movl	20(%esp),%edi
	addl	(%esp),%eax
	adcl	4(%esp),%ebx
	orl	%esi,%ecx
	orl	%edi,%edx
	andl	24(%esp),%ecx
	andl	28(%esp),%edx
	andl	8(%esp),%esi
	andl	12(%esp),%edi
	orl	%esi,%ecx
	orl	%edi,%edx
	addl	%ecx,%eax
	adcl	%edx,%ebx
	movl	%eax,(%esp)
	movl	%ebx,4(%esp)
	movb	(%ebp),%dl
	subl	$8,%esp
	leal	8(%ebp),%ebp
	cmpb	$148,%dl
	jne	L00600_15_x86
.align	4,0x90
L00716_79_x86:
	movl	312(%esp),%ecx
	movl	316(%esp),%edx
	movl	%ecx,%esi
	shrl	$1,%ecx
	movl	%edx,%edi
	shrl	$1,%edx
	movl	%ecx,%eax
	shll	$24,%esi
	movl	%edx,%ebx
	shll	$24,%edi
	xorl	%esi,%ebx
	shrl	$6,%ecx
	xorl	%edi,%eax
	shrl	$6,%edx
	xorl	%ecx,%eax
	shll	$7,%esi
	xorl	%edx,%ebx
	shll	$1,%edi
	xorl	%esi,%ebx
	shrl	$1,%ecx
	xorl	%edi,%eax
	shrl	$1,%edx
	xorl	%ecx,%eax
	shll	$6,%edi
	xorl	%edx,%ebx
	xorl	%edi,%eax
	movl	%eax,(%esp)
	movl	%ebx,4(%esp)
	movl	208(%esp),%ecx
	movl	212(%esp),%edx
	movl	%ecx,%esi
	shrl	$6,%ecx
	movl	%edx,%edi
	shrl	$6,%edx
	movl	%ecx,%eax
	shll	$3,%esi
	movl	%edx,%ebx
	shll	$3,%edi
	xorl	%esi,%eax
	shrl	$13,%ecx
	xorl	%edi,%ebx
	shrl	$13,%edx
	xorl	%ecx,%eax
	shll	$10,%esi
	xorl	%edx,%ebx
	shll	$10,%edi
	xorl	%esi,%ebx
	shrl	$10,%ecx
	xorl	%edi,%eax
	shrl	$10,%edx
	xorl	%ecx,%ebx
	shll	$13,%edi
	xorl	%edx,%eax
	xorl	%edi,%eax
	movl	320(%esp),%ecx
	movl	324(%esp),%edx
	addl	(%esp),%eax
	adcl	4(%esp),%ebx
	movl	248(%esp),%esi
	movl	252(%esp),%edi
	addl	%ecx,%eax
	adcl	%edx,%ebx
	addl	%esi,%eax
	adcl	%edi,%ebx
	movl	%eax,192(%esp)
	movl	%ebx,196(%esp)
	movl	40(%esp),%ecx
	movl	44(%esp),%edx
	movl	%ecx,%esi
	shrl	$9,%ecx
	movl	%edx,%edi
	shrl	$9,%edx
	movl	%ecx,%ebx
	shll	$14,%esi
	movl	%edx,%eax
	shll	$14,%edi
	xorl	%esi,%ebx
	shrl	$5,%ecx
	xorl	%edi,%eax
	shrl	$5,%edx
	xorl	%ecx,%eax
	shll	$4,%esi
	xorl	%edx,%ebx
	shll	$4,%edi
	xorl	%esi,%ebx
	shrl	$4,%ecx
	xorl	%edi,%eax
	shrl	$4,%edx
	xorl	%ecx,%eax
	shll	$5,%esi
	xorl	%edx,%ebx
	shll	$5,%edi
	xorl	%esi,%eax
	xorl	%edi,%ebx
	movl	48(%esp),%ecx
	movl	52(%esp),%edx
	movl	56(%esp),%esi
	movl	60(%esp),%edi
	addl	64(%esp),%eax
	adcl	68(%esp),%ebx
	xorl	%esi,%ecx
	xorl	%edi,%edx
	andl	40(%esp),%ecx
	andl	44(%esp),%edx
	addl	192(%esp),%eax
	adcl	196(%esp),%ebx
	xorl	%esi,%ecx
	xorl	%edi,%edx
	movl	(%ebp),%esi
	movl	4(%ebp),%edi
	addl	%ecx,%eax
	adcl	%edx,%ebx
	movl	32(%esp),%ecx
	movl	36(%esp),%edx
	addl	%esi,%eax
	adcl	%edi,%ebx
	movl	%eax,(%esp)
	movl	%ebx,4(%esp)
	addl	%ecx,%eax
	adcl	%edx,%ebx
	movl	8(%esp),%ecx
	movl	12(%esp),%edx
	movl	%eax,32(%esp)
	movl	%ebx,36(%esp)
	movl	%ecx,%esi
	shrl	$2,%ecx
	movl	%edx,%edi
	shrl	$2,%edx
	movl	%ecx,%ebx
	shll	$4,%esi
	movl	%edx,%eax
	shll	$4,%edi
	xorl	%esi,%ebx
	shrl	$5,%ecx
	xorl	%edi,%eax
	shrl	$5,%edx
	xorl	%ecx,%ebx
	shll	$21,%esi
	xorl	%edx,%eax
	shll	$21,%edi
	xorl	%esi,%eax
	shrl	$21,%ecx
	xorl	%edi,%ebx
	shrl	$21,%edx
	xorl	%ecx,%eax
	shll	$5,%esi
	xorl	%edx,%ebx
	shll	$5,%edi
	xorl	%esi,%eax
	xorl	%edi,%ebx
	movl	8(%esp),%ecx
	movl	12(%esp),%edx
	movl	16(%esp),%esi
	movl	20(%esp),%edi
	addl	(%esp),%eax
	adcl	4(%esp),%ebx
	orl	%esi,%ecx
	orl	%edi,%edx
	andl	24(%esp),%ecx
	andl	28(%esp),%edx
	andl	8(%esp),%esi
	andl	12(%esp),%edi
	orl	%esi,%ecx
	orl	%edi,%edx
	addl	%ecx,%eax
	adcl	%edx,%ebx
	movl	%eax,(%esp)
	movl	%ebx,4(%esp)
	movb	(%ebp),%dl
	subl	$8,%esp
	leal	8(%ebp),%ebp
	cmpb	$23,%dl
	jne	L00716_79_x86
	movl	840(%esp),%esi
	movl	844(%esp),%edi
	movl	(%esi),%eax
	movl	4(%esi),%ebx
	movl	8(%esi),%ecx
	movl	12(%esi),%edx
	addl	8(%esp),%eax
	adcl	12(%esp),%ebx
	movl	%eax,(%esi)
	movl	%ebx,4(%esi)
	addl	16(%esp),%ecx
	adcl	20(%esp),%edx
	movl	%ecx,8(%esi)
	movl	%edx,12(%esi)
	movl	16(%esi),%eax
	movl	20(%esi),%ebx
	movl	24(%esi),%ecx
	movl	28(%esi),%edx
	addl	24(%esp),%eax
	adcl	28(%esp),%ebx
	movl	%eax,16(%esi)
	movl	%ebx,20(%esi)
	addl	32(%esp),%ecx
	adcl	36(%esp),%edx
	movl	%ecx,24(%esi)
	movl	%edx,28(%esi)
	movl	32(%esi),%eax
	movl	36(%esi),%ebx
	movl	40(%esi),%ecx
	movl	44(%esi),%edx
	addl	40(%esp),%eax
	adcl	44(%esp),%ebx
	movl	%eax,32(%esi)
	movl	%ebx,36(%esi)
	addl	48(%esp),%ecx
	adcl	52(%esp),%edx
	movl	%ecx,40(%esi)
	movl	%edx,44(%esi)
	movl	48(%esi),%eax
	movl	52(%esi),%ebx
	movl	56(%esi),%ecx
	movl	60(%esi),%edx
	addl	56(%esp),%eax
	adcl	60(%esp),%ebx
	movl	%eax,48(%esi)
	movl	%ebx,52(%esi)
	addl	64(%esp),%ecx
	adcl	68(%esp),%edx
	movl	%ecx,56(%esi)
	movl	%edx,60(%esi)
	addl	$840,%esp
	subl	$640,%ebp
	cmpl	8(%esp),%edi
	jb	L002loop_x86
	movl	12(%esp),%esp
	popl	%edi
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret
.align	6,0x90
L001K512:
.long	3609767458,1116352408
.long	602891725,1899447441
.long	3964484399,3049323471
.long	2173295548,3921009573
.long	4081628472,961987163
.long	3053834265,1508970993
.long	2937671579,2453635748
.long	3664609560,2870763221
.long	2734883394,3624381080
.long	1164996542,310598401
.long	1323610764,607225278
.long	3590304994,1426881987
.long	4068182383,1925078388
.long	991336113,2162078206
.long	633803317,2614888103
.long	3479774868,3248222580
.long	2666613458,3835390401
.long	944711139,4022224774
.long	2341262773,264347078
.long	2007800933,604807628
.long	1495990901,770255983
.long	1856431235,1249150122
.long	3175218132,1555081692
.long	2198950837,1996064986
.long	3999719339,2554220882
.long	766784016,2821834349
.long	2566594879,2952996808
.long	3203337956,3210313671
.long	1034457026,3336571891
.long	2466948901,3584528711
.long	3758326383,113926993
.long	168717936,338241895
.long	1188179964,666307205
.long	1546045734,773529912
.long	1522805485,1294757372
.long	2643833823,1396182291
.long	2343527390,1695183700
.long	1014477480,1986661051
.long	1206759142,2177026350
.long	344077627,2456956037
.long	1290863460,2730485921
.long	3158454273,2820302411
.long	3505952657,3259730800
.long	106217008,3345764771
.long	3606008344,3516065817
.long	1432725776,3600352804
.long	1467031594,4094571909
.long	851169720,275423344
.long	3100823752,430227734
.long	1363258195,506948616
.long	3750685593,659060556
.long	3785050280,883997877
.long	3318307427,958139571
.long	3812723403,1322822218
.long	2003034995,1537002063
.long	3602036899,1747873779
.long	1575990012,1955562222
.long	1125592928,2024104815
.long	2716904306,2227730452
.long	442776044,2361852424
.long	593698344,2428436474
.long	3733110249,2756734187
.long	2999351573,3204031479
.long	3815920427,3329325298
.long	3928383900,3391569614
.long	566280711,3515267271
.long	3454069534,3940187606
.long	4000239992,4118630271
.long	1914138554,116418474
.long	2731055270,174292421
.long	3203993006,289380356
.long	320620315,460393269
.long	587496836,685471733
.long	1086792851,852142971
.long	365543100,1017036298
.long	2618297676,1126000580
.long	3409855158,1288033470
.long	4234509866,1501505948
.long	987167468,1607167915
.long	1246189591,1816402316
.byte	83,72,65,53,49,50,32,98,108,111,99,107,32,116,114,97
.byte	110,115,102,111,114,109,32,102,111,114,32,120,56,54,44,32
.byte	67,82,89,80,84,79,71,65,77,83,32,98,121,32,60,97
.byte	112,112,114,111,64,111,112,101,110,115,115,108,46,111,114,103
.byte	62,0
.section __IMPORT,__pointers,non_lazy_symbol_pointers
L_OPENSSL_ia32cap_P$non_lazy_ptr:
.indirect_symbol	_OPENSSL_ia32cap_P
.long	0
.comm	_OPENSSL_ia32cap_P,8,2
