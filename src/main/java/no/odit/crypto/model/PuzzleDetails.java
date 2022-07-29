package no.odit.crypto.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;

import java.math.BigInteger;

@AllArgsConstructor
@RequiredArgsConstructor
@Data
@Builder
public class PuzzleDetails {

    private BigInteger n;

    private BigInteger t;

    private BigInteger z;

}