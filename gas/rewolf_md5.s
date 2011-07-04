#
#---------------------------------------------------------------------------
#                     The MD5 Message-Digest Algorithm                     |
#---------------------------------------------------------------------------
#   Description:                                                           |
#   ============                                                           |
#                                                                          |
#   The MD5 algorithm is designed to be quite fast on 32-bit machines. In  |
#   addition,  the MD5 algorithm  does not require any large substitution  |
#   tables, the algorithm can be coded quite compactly.                    |
#                                                                          |
#   The MD5 algorithm is an extension of the MD4 message-digest algorithm  |
#   1,2]. MD5 is  slightly slower than MD4, but is more "conservative" in  |
#   design. MD5  was designed  because it  was felt  that MD4 was perhaps  |
#   being adopted  for use more  quickly than  justified by  the existing  |
#   critical  review, because MD4  was designed to be exceptionally fast,  |
#   it  is "at the edge"  in terms of  risking  successful  cryptanalytic  |
#   attack.  MD5 backs off  a bit, giving up a little in speed for a much  |
#   greater   likelihood  of  ultimate  security.  It  incorporates  some  |
#   suggestions  made  by  various  reviewers,  and  contains  additional  |
#   optimizations. The MD5 algorithm is being placed in the public domain  |
#   for review and possible adoption as a standard.                        |
#                                                                          |
#---------------------------------------------------------------------------
#   Implementation based on rfc1321 (fully rewritten in asm, not ripped :))|
#---------------------------------------------------------------------------
#   Usage:                                                                 |
#   ======                                                                 |
#                                                                          |
#   Simply include this file to your project:                              |
#   exp: include \..path..\rewolf_md5.s                                    |
#                                                                          |
#   Target compiler...: GNU ASM                                            |
#   Calling convention:                                                    |
#                                                                          |
#       push    size of datablock                                          |
#       push    offset datablock                                           |
#       push    offset destHash                                            |
#       call    _rwf_md5                                                   |
#                                                                          |
#   datablock -> (input)  -> buffer that contains data to hash             |
#   destHash  -> (output) -> 16-bytes buffer for hashed data               |
#                                                                          |
#   Modified registers: none                                               |
#   Stack is automatically cleared                                         |
#---------------------------------------------------------------------------
#   Coder.: ReWolf^HTB                                                     |
#   Date..: 17.XII.2004                                                    |
#   E-mail: rewolf@poczta.onet.pl                                          |
#   WWW...: http://www.rewolf.prv.pl                                       |
#---------------------------------------------------------------------------
#   Adaptation for GNU Assembler: Hannes Beinert (21-Jun-11)               |
#---------------------------------------------------------------------------

S11 =  7
S12 = 12
S13 = 17
S14 = 22
S21 =  5
S22 =  9
S23 = 14
S24 = 20
S31 =  4
S32 = 11
S33 = 16
S34 = 23
S41 =  6
S42 = 10
S43 = 15
S44 = 21

#
# Define macros to implement auxiliary functions as
# described in RFC1321 (cf 3.4)
#

.macro FF a,b,c,d,k,s,i
	mov	\b, %edi
	mov	\b, %ebp
	and	\c, %edi
	not	%ebp
	and	\d, %ebp
	or	%ebp, %edi
	leal	\i(\a, %edi,), \a
	addl	\k*4(%esi), \a
	rol	$\s, \a
	add	\b, \a
.endm

.macro GG a,b,c,d,k,s,i
	mov	\d, %edi
	mov	\d, %ebp
	and	\b, %edi
	not	%ebp
	and	\c, %ebp
	or	%ebp, %edi
	leal	\i(\a, %edi,), \a
	addl	\k*4(%esi), \a
	rol	$\s, \a
	add	\b, \a
.endm

.macro HH a,b,c,d,k,s,i
	mov	\b, %ebp
	xor	\c, %ebp
	xor	\d, %ebp
	leal	\i(\a, %ebp,), \a
	addl	\k*4(%esi), \a
	rol	$\s, \a
	add	\b, \a
.endm

.macro II a,b,c,d,k,s,i
	mov	\d, %ebp
	not	%ebp
	or	\b, %ebp
	xor	\c, %ebp
	leal	\i(\a, %ebp,), \a
	addl	\k*4(%esi), \a
	rol	$\s, \a
	add	\b, \a
.endm

#
# md5 Main Entry Point
# --------------------
#
# Calling convention:
#		+----------------------------+
#	esp+16:	+   Length(Input message)    |
#		+----------------------------+
#	esp+08	+   Address(Input message)   |
#		+----------------------------+
#	esp+04:	+   Address(MD5 buffer)      |
#		+----------------------------+
#	esp:	+   Return address           |
#		+----------------------------+
#
# NB: Some comments refer to steps in the MD5 algorithm detailed in RFC1321 to
# help annotate the goings-on.
#

ARG_MDBADR	= 0x04				# Stack offset to A(MD buffer)
ARG_MSGADR	= 0x08				# Stack offset to A(Input message)
ARG_MSGLEN	= 0x0C				# Stack offset to L(Input message)

.text
.global	_rwf_md5

_rwf_md5:
	pushal

	movl	ARG_MDBADR + 8*4(%esp), %esi	# esi = arg A(MD buffer)
	movl	$0x067452301, (%esi)		# Initialize MD buffer (cf 3.3)
	movl	$0x0EFCDAB89, 0x04(%esi)	#	Magic numbers from RFC
	movl	$0x098BADCFE, 0x08(%esi)
	movl	$0x010325476, 0x0C(%esi)

	#
	# Take each 512-bit chunk of the input
	# buffer and process it into the digest.
	# When we get to the last chunk, we will
	# append the padding bits & input length
	# to obtain another complete 512b chunk.
	#
	# NB: If the input data is a precise
	# multiple of 512b, then the last chunk
	# will consist only of padding & length.
	# 

	movl	ARG_MSGLEN + 8*4(%esp), %eax	# eax = arg L(input buffer)
	push	%eax
	xor	%edx, %edx			# Calculate input length in 512-bit chunks + 1
	movl	$64, %ecx
	div	%ecx
	inc	%eax				# eax = Number of chunks + 1
	pop	%edx
	subl	$64, %esp			# Reserve chunk buffer on stack (16*4B = 512b)
	mov	%esp, %ebx			#    ebx = A(chunk buffer)
	movl	ARG_MSGADR+(8+16)*4(%esp), %esi	# esi = arg A(input buffer)
	xchg	%edx, %eax			# eax = L(input); edx = # 512b chunks + 1

	#
	# Start a new message chunk
	#
	# There are four cases we must handle:
	#
	#			Message	Padding	Length
	#			-------	-------	------
	#	1.    Full:	    64	    0	   0
	#	2. Partial:	 56-63	  8-1	   0
	#	3. Partial:	  1-55	 55-1	   8
	#	4.   Empty:	     0	   56	   8
	#
	# NB: The first padding byte is required & special (0x80), while
	# the remaining padding bytes are zero and optional.  Hence, the
	# last chunk must have enough space for at least 1 padding byte,
	# plus the 8-byte message length.
	#
	# In the following code, the following register assignments are
	# generally maintained:
	#
	#	eax = Remaining number of bytes in message
	#	ebx = A(chunk buffer on stack)
	#	edx = Number of remaining message chunks
	#	esi = A(current position in input message buffer)
	#
_n0:
	mov	%ebx, %edi			# edi = A(chunk buffer)
	dec	%edx				# Any more message chunks to process?
	jne	_n1				#	Jump if we're not done
	test	%eax, %eax			# Last or second to last chunk.  Have we added pad?
	js	_nD				#	Jump if we've already added 1st pad byte
	movb	$0x80, (%ebx,%eax,)		# Append initial padding after data (cf 3.1)
	jmp	_nC				#	Go process partial chunk

	#
	# We are dealing with either the last, or the second to
	# last chunk.  In other words, either a partial chunk,
	# or an empty chunk.  Upon entry to this section:
	#
	#   If...	    Then...
	#   -------------   --------------------------------------
	#   eax < 0	    Empty block, 1st pad was in last chunk
	#   eax = 0	    Empty block, 1st pad in *this* chunk
	#   1 <= eax <=63   Partial block, 1st pad in this chunk
	#
_nD:
	xor	%eax, %eax			# We've already added the pad byte
	dec	%eax				# Jigger eax so we clear the entire chunk
_nC:
	mov	$64, %ecx			# Full message chunk is 64-bytes, or 512-bits
	sub	%eax, %ecx			# ecx = L(padding bytes in chunk)
	add	%eax, %edi			# edi = A(first padding byte)
	push	%eax
	xor	%eax, %eax
	inc	%edi				# edi = A(second padding byte)
	dec	%ecx				# ecx = L(padding bytes to be cleared)
	rep	stosb				# Clear padding bytes (fill ecx bytes @edi with al)
	pop	%eax				# eax = L(message bytes remaining)
	test	%eax, %eax			# Was the 1st padding byte appended in last chunk?
	js	_nB				#	Jump if yes, and go append message length
	cmp	$56, %eax			# Enough space to append length to partial chunk?
	jnb	_nE				#	Jump if not enough.  We need another chunk.

	#
	# Append message length into current
	# message chunk, as per RFC...
	#
_nB:
        push	%eax
	movl	ARG_MSGLEN+(8+16+1)*4(%esp), %eax # eax = arg L(Input message)
	push	%edx
	xor	%edx, %edx
	movl	$8, %ecx
	mul	%ecx				# edx:eax = Total number of bits in message
	mov	%eax, 56(%ebx)			# Append message length to message (cf 3.2)
	mov	%edx, 60(%ebx)			#	Low order, then high order
	pop	%edx				# Restore edx = remaining message chunks
	pop	%eax				# Restore eax = remaining message bytes
	jmp	_n1				# Now fill in message data into this chunk

	#
	# Complete the current message chunk by
	# copying in message data from the current
	# position in the message buffer.
	#
_nE:
	inc	%edx				# We need another empty chunk for message length
_n1:
	test	%eax, %eax			# Do we have more message data?
	js	_nA				#	Jump if no more data
	cmp	$64, %eax			# Do we have at least 512-bits of data?
	jnb	_n2				#	Jump if we have a full chunk
	jmp	_n10				# This is will be a partial chunk
_nA:
	xor	%eax, %eax			# eax = 0; Remaining message bytes
_n10:
	mov	%eax, %ecx			# ecx = L(message bytes to process)
	jmp	_n3
_n2:
	mov	$64, %ecx			# ecx = 64 bytes; Process a full 512b chunk
_n3:
	mov	%ebx, %edi			# edi = A(chunk buffer)
	rep	movsb				# Copy message to chunk buffer (ecx bytes from esi -> edi)
	push	%eax
	push	%edx
	push	%ebx		# ??? Isn't ebx == A(chunk buffer)?  Why leal needed?
	push	%esi
	leal	0x10(%esp), %esi		   # esi = A(chunk buffer); Recover values after rep
	movl	ARG_MDBADR+(4+16+8)*4(%esp), %edi  # edi = A(MD buffer)
	push	%edi

	#
	# Process message chunk by performing
	# four rounds of state transformations.
	# (cf 3.4)
	#

	movl	(%edi), %eax			# Load current MD buffer into registers
	movl	0x04(%edi), %ebx
	movl	0x08(%edi), %ecx
	movl	0x0C(%edi), %edx

	FF	%eax, %ebx, %ecx, %edx,  0, S11, 0x0d76aa478	# Round 1
	FF	%edx, %eax, %ebx, %ecx,  1, S12, 0x0e8c7b756
	FF	%ecx, %edx, %eax, %ebx,  2, S13, 0x0242070db
	FF	%ebx, %ecx, %edx, %eax,  3, S14, 0x0c1bdceee
	FF	%eax, %ebx, %ecx, %edx,  4, S11, 0x0f57c0faf
	FF	%edx, %eax, %ebx, %ecx,  5, S12, 0x04787c62a
	FF	%ecx, %edx, %eax, %ebx,  6, S13, 0x0a8304613
	FF	%ebx, %ecx, %edx, %eax,  7, S14, 0x0fd469501
	FF	%eax, %ebx, %ecx, %edx,  8, S11, 0x0698098d8
	FF	%edx, %eax, %ebx, %ecx,  9, S12, 0x08b44f7af
	FF	%ecx, %edx, %eax, %ebx, 10, S13, 0x0ffff5bb1
	FF	%ebx, %ecx, %edx, %eax, 11, S14, 0x0895cd7be
	FF	%eax, %ebx, %ecx, %edx, 12, S11, 0x06b901122
	FF	%edx, %eax, %ebx, %ecx, 13, S12, 0x0fd987193
	FF	%ecx, %edx, %eax, %ebx, 14, S13, 0x0a679438e
	FF	%ebx, %ecx, %edx, %eax, 15, S14, 0x049b40821

	GG	%eax, %ebx, %ecx, %edx,  1, S21, 0x0f61e2562	# Round 2
	GG	%edx, %eax, %ebx, %ecx,  6, S22, 0x0c040b340
	GG	%ecx, %edx, %eax, %ebx, 11, S23, 0x0265e5a51
	GG	%ebx, %ecx, %edx, %eax,  0, S24, 0x0e9b6c7aa
	GG	%eax, %ebx, %ecx, %edx,  5, S21, 0x0d62f105d
	GG	%edx, %eax, %ebx, %ecx, 10, S22, 0x002441453
	GG	%ecx, %edx, %eax, %ebx, 15, S23, 0x0d8a1e681
	GG	%ebx, %ecx, %edx, %eax,  4, S24, 0x0e7d3fbc8
	GG	%eax, %ebx, %ecx, %edx,  9, S21, 0x021e1cde6
	GG	%edx, %eax, %ebx, %ecx, 14, S22, 0x0c33707d6
	GG	%ecx, %edx, %eax, %ebx,  3, S23, 0x0f4d50d87
	GG	%ebx, %ecx, %edx, %eax,  8, S24, 0x0455a14ed
	GG	%eax, %ebx, %ecx, %edx, 13, S21, 0x0a9e3e905
	GG	%edx, %eax, %ebx, %ecx,  2, S22, 0x0fcefa3f8
	GG	%ecx, %edx, %eax, %ebx,  7, S23, 0x0676f02d9
	GG	%ebx, %ecx, %edx, %eax, 12, S24, 0x08d2a4c8a

	HH	%eax, %ebx, %ecx, %edx,  5, S31, 0x0fffa3942	# Round 3
	HH	%edx, %eax, %ebx, %ecx,  8, S32, 0x08771f681
	HH	%ecx, %edx, %eax, %ebx, 11, S33, 0x06d9d6122
	HH	%ebx, %ecx, %edx, %eax, 14, S34, 0x0fde5380c
	HH	%eax, %ebx, %ecx, %edx,  1, S31, 0x0a4beea44
	HH	%edx, %eax, %ebx, %ecx,  4, S32, 0x04bdecfa9
	HH	%ecx, %edx, %eax, %ebx,  7, S33, 0x0f6bb4b60
	HH	%ebx, %ecx, %edx, %eax, 10, S34, 0x0bebfbc70
	HH	%eax, %ebx, %ecx, %edx, 13, S31, 0x0289b7ec6
	HH	%edx, %eax, %ebx, %ecx,  0, S32, 0x0eaa127fa
	HH	%ecx, %edx, %eax, %ebx,  3, S33, 0x0d4ef3085
	HH	%ebx, %ecx, %edx, %eax,  6, S34, 0x004881d05
	HH	%eax, %ebx, %ecx, %edx,  9, S31, 0x0d9d4d039
	HH	%edx, %eax, %ebx, %ecx, 12, S32, 0x0e6db99e5
	HH	%ecx, %edx, %eax, %ebx, 15, S33, 0x01fa27cf8
	HH	%ebx, %ecx, %edx, %eax,  2, S34, 0x0c4ac5665

	II	%eax, %ebx, %ecx, %edx,  0, S41, 0x0f4292244	# Round 4
	II	%edx, %eax, %ebx, %ecx,  7, S42, 0x0432aff97
	II	%ecx, %edx, %eax, %ebx, 14, S43, 0x0ab9423a7
	II	%ebx, %ecx, %edx, %eax,  5, S44, 0x0fc93a039
	II	%eax, %ebx, %ecx, %edx, 12, S41, 0x0655b59c3
	II	%edx, %eax, %ebx, %ecx,  3, S42, 0x08f0ccc92
	II	%ecx, %edx, %eax, %ebx, 10, S43, 0x0ffeff47d
	II	%ebx, %ecx, %edx, %eax,  1, S44, 0x085845dd1
	II	%eax, %ebx, %ecx, %edx,  8, S41, 0x06fa87e4f
	II	%edx, %eax, %ebx, %ecx, 15, S42, 0x0fe2ce6e0
	II	%ecx, %edx, %eax, %ebx,  6, S43, 0x0a3014314
	II	%ebx, %ecx, %edx, %eax, 13, S44, 0x04e0811a1
	II	%eax, %ebx, %ecx, %edx,  4, S41, 0x0f7537e82
	II	%edx, %eax, %ebx, %ecx, 11, S42, 0x0bd3af235
	II	%ecx, %edx, %eax, %ebx,  2, S43, 0x02ad7d2bb
	II	%ebx, %ecx, %edx, %eax,  9, S44, 0x0eb86d391

	pop	%edi				# Restore edi = A(MD buffer)
	add	%eax, (%edi)			# Update digest w/results of rounds
	add	%ebx, 0x04(%edi)
	add	%ecx, 0x08(%edi)
	add	%edx, 0x0C(%edi)

	pop	%esi				# esi = A(current position in message)
	pop	%ebx				# ebx = A(chunk buffer)
	pop	%edx				# edx = Number chunks remaining
	pop	%eax				# eax = Number message bytes remaining

	sub	$64, %eax			# We've just finished 64-bytes of message
	test	%edx, %edx			# Do we have more message chunks left?
	jne	_n0				#	Jump if we have more

	add	$64, %esp			# Nope.  All done.  Deallocate chunk buffer
	popal					# Restore registers
	ret	$12				# Return to papa

	.end
