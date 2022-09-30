package no.odit.crypto.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;

import java.math.BigInteger;
import java.time.Duration;
import java.time.LocalDate;
import java.time.LocalTime;

@AllArgsConstructor
@RequiredArgsConstructor
@Data
@Builder
public class EncryptionDetails {

    private String fileName;

    private BigInteger n;

    private BigInteger t;

    private BigInteger z;

    private LocalDate date;

    private LocalTime time;

    private Duration duration;

    private String ivParameterSpec;

}