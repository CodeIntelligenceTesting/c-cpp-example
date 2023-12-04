//
// Created by philip on 22/11/23.
//

#include <stdio.h>
#include <string.h>
#include "person.h"



char* getPersonsName(const Person* person) {
    return (char *) &person->name;
}
int getPersonsAge(const Person* person) {
    return person->age;
}

void setPersonsName(Person* person, const char* name){
    strcpy(person->name, name);
}
void setPersonsAge(Person* person, int age){
    person->age = age;
}